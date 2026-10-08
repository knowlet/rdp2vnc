use crate::{framebuffer::Frame, input::Handler, rfb::Input};
use anyhow::{Context, Result};
use async_trait::async_trait;
use ironrdp_server::{
    BitmapUpdate, ConnectionHandler, ConnectionInfo, Credentials, DesktopSize, DisplayUpdate,
    PixelFormat, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, ServerResult,
};
use std::{
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc, watch},
};
use tokio_rustls::TlsAcceptor;

struct Display {
    frames: watch::Receiver<Arc<Frame>>,
}
struct Updates {
    frames: watch::Receiver<Arc<Frame>>,
    first: bool,
    size: (u16, u16),
    pending: Option<Arc<Frame>>,
}
#[async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        let f = self.frames.borrow();
        DesktopSize {
            width: f.width,
            height: f.height,
        }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        let f = self.frames.borrow();
        Ok(Box::new(Updates {
            frames: self.frames.clone(),
            first: true,
            size: (f.width, f.height),
            pending: None,
        }))
    }
}
fn bitmap(frame: Arc<Frame>) -> DisplayUpdate {
    DisplayUpdate::Bitmap(BitmapUpdate {
        x: 0,
        y: 0,
        width: NonZeroU16::new(frame.width).expect("validated width"),
        height: NonZeroU16::new(frame.height).expect("validated height"),
        format: PixelFormat::BgrX32,
        data: bytes::Bytes::copy_from_slice(&frame.pixels),
        stride: NonZeroUsize::new(usize::from(frame.width) * 4).expect("validated stride"),
    })
}
#[async_trait]
impl RdpServerDisplayUpdates for Updates {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        if let Some(frame) = self.pending.take() {
            return Ok(Some(bitmap(frame)));
        }
        if !self.first && self.frames.changed().await.is_err() {
            return Ok(None);
        }
        self.first = false;
        let frame = self.frames.borrow_and_update().clone();
        let size = (frame.width, frame.height);
        if size != self.size {
            self.size = size;
            self.pending = Some(frame);
            return Ok(Some(DisplayUpdate::Resize(DesktopSize {
                width: size.0,
                height: size.1,
            })));
        }
        Ok(Some(bitmap(frame)))
    }
}
struct Lifecycle {
    authenticated: Arc<Notify>,
}
impl ConnectionHandler for Lifecycle {
    fn on_connection_info(&mut self, _info: &ConnectionInfo) {
        self.authenticated.notify_one();
    }
}

pub struct Settings {
    pub listen: SocketAddr,
    pub tls: TlsAcceptor,
    pub public_key: Vec<u8>,
    pub credentials: Credentials,
    pub read_only: bool,
    pub mac: bool,
}

async fn serve(
    stream: TcpStream,
    settings: &Settings,
    frames: watch::Receiver<Arc<Frame>>,
    inputs: mpsc::Sender<Input>,
    fatal: Arc<Notify>,
) -> Result<()> {
    let authenticated = Arc::new(Notify::new());
    let mut server = RdpServer::builder()
        .with_addr(settings.listen)
        .with_hybrid(settings.tls.clone(), settings.public_key.clone())
        .with_input_handler(Handler::new(
            inputs.clone(),
            fatal,
            settings.read_only,
            settings.mac,
        ))
        .with_display_handler(Display { frames })
        .with_connection_handler(Some(Box::new(Lifecycle {
            authenticated: authenticated.clone(),
        })))
        .build();
    server.set_credentials(Some(settings.credentials.clone()));
    // No legacy security, no TLS-only fallback, and no automatic-reconnect
    // cookie that could bypass credential validation.
    let deadline = async {
        tokio::select! {
            _=authenticated.notified()=>std::future::pending::<()>().await,
            _=tokio::time::sleep(Duration::from_secs(30))=>{},
        }
    };
    tokio::select! {
        result=server.run_connection(stream)=>result.context("RDP connection ended"),
        _=deadline=>Err(anyhow::anyhow!("RDP authentication timed out")),
    }
}

/// Single desktop, one active RDP client. Extra TCP connections are closed
/// instead of retaining an unbounded queue. A new client gets a full snapshot.
pub async fn run(
    listener: TcpListener,
    settings: Settings,
    frames: watch::Receiver<Arc<Frame>>,
    inputs: mpsc::Sender<Input>,
    fatal: Arc<Notify>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tracing::info!(%peer,"RDP client connected; authenticating");
        let connection = serve(
            stream,
            &settings,
            frames.clone(),
            inputs.clone(),
            fatal.clone(),
        );
        tokio::pin!(connection);
        let outcome = loop {
            tokio::select! {
                result=&mut connection=>break result,
                extra=listener.accept()=>{let(stream,_)=extra?;drop(stream);},
            }
        };
        inputs
            .send(Input::Reset)
            .await
            .context("VNC input writer stopped")?;
        if let Err(error) = outcome {
            tracing::warn!(%peer,%error,"RDP session closed");
        } else {
            tracing::info!(%peer,"RDP client disconnected");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_late_rdp_client_receives_a_complete_snapshot() {
        let mut frame = Frame::new(3840, 2160).unwrap();
        frame.pixels[0] = 42;
        let (_tx, rx) = watch::channel(Arc::new(frame));
        let mut display = Display { frames: rx };
        let mut updates = display.updates().await.unwrap();
        let Some(DisplayUpdate::Bitmap(update)) = updates.next_update().await.unwrap() else {
            panic!("no snapshot")
        };
        assert_eq!(update.width.get(), 3840);
        assert_eq!(update.stride.get(), 15360);
        assert_eq!(update.data[0], 42);
    }
    #[tokio::test]
    async fn resize_precedes_pixels() {
        let (tx, rx) = watch::channel(Arc::new(Frame::new(640, 480).unwrap()));
        let mut display = Display { frames: rx };
        let mut updates = display.updates().await.unwrap();
        updates.next_update().await.unwrap();
        tx.send_replace(Arc::new(Frame::new(800, 600).unwrap()));
        assert!(matches!(
            updates.next_update().await.unwrap(),
            Some(DisplayUpdate::Resize(_))
        ));
        assert!(matches!(
            updates.next_update().await.unwrap(),
            Some(DisplayUpdate::Bitmap(_))
        ));
    }
}
