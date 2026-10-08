use crate::{framebuffer::Frame, input::Handler, rfb::Input};
use anyhow::{Context, Result};
use async_trait::async_trait;
use ironrdp_server::{
    BitmapUpdate, ConnectionHandler, ConnectionInfo, Credentials, DesktopSize, DisplayUpdate,
    KeyboardEvent, MouseEvent, PixelFormat, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates,
    RdpServerInputHandler, ServerError, ServerErrorExt, ServerResult,
};
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc, watch},
};
use tokio_rustls::TlsAcceptor;

struct Display {
    frames: watch::Receiver<Arc<Frame>>,
    negotiated_size: Arc<Mutex<Option<(u16, u16)>>>,
    admission: Option<Arc<Admission>>,
}
impl Display {
    fn new(frames: watch::Receiver<Arc<Frame>>) -> Self {
        Self {
            frames,
            negotiated_size: Arc::new(Mutex::new(None)),
            admission: None,
        }
    }
    fn dimensions(&self) -> (u16, u16) {
        let mut size = self.negotiated_size.lock().expect("display size lock");
        *size.get_or_insert_with(|| {
            let frame = self.frames.borrow();
            (frame.width, frame.height)
        })
    }
}
struct Updates {
    frames: watch::Receiver<Arc<Frame>>,
    first: bool,
    size: (u16, u16),
    negotiated_size: Arc<Mutex<Option<(u16, u16)>>>,
    pending: Option<Arc<Frame>>,
}
#[async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        // IronRDP reads this both for negotiation and encoder setup. Keep
        // their dimensions consistent until an explicit resize is emitted.
        let (width, height) = self.dimensions();
        DesktopSize { width, height }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        if self
            .admission
            .as_ref()
            .is_some_and(|a| !a.admitted.load(Ordering::Acquire))
        {
            return Err(ServerError::reason("session admission", "desktop is busy"));
        }
        Ok(Box::new(Updates {
            frames: self.frames.clone(),
            first: true,
            size: self.dimensions(),
            negotiated_size: self.negotiated_size.clone(),
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
            *self.negotiated_size.lock().expect("display size lock") = Some(size);
            self.pending = Some(frame);
            return Ok(Some(DisplayUpdate::Resize(DesktopSize {
                width: size.0,
                height: size.1,
            })));
        }
        Ok(Some(bitmap(frame)))
    }
}
// The pinned IronRDP callback runs after credential validation and before
// buffered input is dispatched. Claim the desktop synchronously in that hook:
// cancelling a losing future later is too late to prevent input leakage.
struct Admission {
    active: Arc<AtomicBool>,
    admitted: AtomicBool,
    resolved: Notify,
}
impl Admission {
    fn new(active: Arc<AtomicBool>) -> Self {
        Self {
            active,
            admitted: AtomicBool::new(false),
            resolved: Notify::new(),
        }
    }
    fn authenticate(&self) {
        let admitted = self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        self.admitted.store(admitted, Ordering::Release);
        self.resolved.notify_one();
    }
    async fn finish(&self, inputs: &mpsc::Sender<Input>) -> Result<()> {
        if self.admitted.load(Ordering::Acquire) {
            inputs
                .send(Input::Reset)
                .await
                .context("VNC input writer stopped")?;
            self.admitted.store(false, Ordering::Release);
            self.active.store(false, Ordering::Release);
        }
        Ok(())
    }
}
struct Lifecycle(Arc<Admission>);
impl ConnectionHandler for Lifecycle {
    fn on_connection_info(&mut self, _info: &ConnectionInfo) {
        self.0.authenticate();
    }
}
struct AdmittedInput {
    admission: Arc<Admission>,
    handler: Handler,
}
impl RdpServerInputHandler for AdmittedInput {
    fn keyboard(&mut self, event: KeyboardEvent) {
        if self.admission.admitted.load(Ordering::Acquire) {
            self.handler.keyboard(event);
        }
    }
    fn mouse(&mut self, event: MouseEvent) {
        if self.admission.admitted.load(Ordering::Acquire) {
            self.handler.mouse(event);
        }
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
    admission: Arc<Admission>,
) -> Result<()> {
    let mut display = Display::new(frames);
    display.admission = Some(admission.clone());
    let mut server = RdpServer::builder()
        .with_addr(settings.listen)
        .with_hybrid(settings.tls.clone(), settings.public_key.clone())
        .with_input_handler(AdmittedInput {
            admission: admission.clone(),
            handler: Handler::new(inputs, fatal, settings.read_only, settings.mac),
        })
        .with_display_handler(display)
        .with_connection_handler(Some(Box::new(Lifecycle(admission.clone()))))
        .build();
    server.set_credentials(Some(settings.credentials.clone()));
    // No legacy security, no TLS-only fallback, and no automatic-reconnect
    // cookie that could bypass credential validation.
    let deadline = async {
        tokio::select! {
            _=admission.resolved.notified()=> {
                if admission.admitted.load(Ordering::Acquire) {
                    std::future::pending::<()>().await;
                }
                "RDP desktop already has an authenticated client"
            },
            _=tokio::time::sleep(Duration::from_secs(30))=>"RDP authentication timed out",
        }
    };
    tokio::select! {
        result=server.run_connection(stream)=>result.context("RDP connection ended"),
        reason=deadline=>Err(anyhow::anyhow!(reason)),
    }
}

const MAX_PENDING_AUTHENTICATIONS: usize = 8;
type Connection<'a> = Pin<Box<dyn Future<Output = (SocketAddr, Result<()>, Arc<Admission>)> + 'a>>;

// Poll in this task: the pinned IronRDP session future is deliberately !Send.
// Keeping the collection bounded also bounds socket and handshake state.
async fn completed(
    connections: &mut Vec<Connection<'_>>,
) -> (SocketAddr, Result<()>, Arc<Admission>) {
    poll_fn(|cx| {
        for index in 0..connections.len() {
            if let Poll::Ready(result) = connections[index].as_mut().poll(cx) {
                drop(connections.swap_remove(index));
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    })
    .await
}

/// Single desktop, one authenticated RDP client, bounded parallel handshakes.
/// An idle unauthenticated peer must not reserve the active desktop slot.
pub async fn run(
    listener: TcpListener,
    settings: Settings,
    frames: watch::Receiver<Arc<Frame>>,
    inputs: mpsc::Sender<Input>,
    fatal: Arc<Notify>,
) -> Result<()> {
    let active = Arc::new(AtomicBool::new(false));
    let mut connections: Vec<Connection<'_>> = Vec::new();
    loop {
        tokio::select! {
            (peer, outcome, admission) = completed(&mut connections), if !connections.is_empty() => {
                // Only the winner can have sent input. Queue its reset before
                // releasing admission so a new client's input cannot overtake it.
                admission.finish(&inputs).await?;
                if let Err(error) = outcome {
                    tracing::warn!(%peer,%error,"RDP session closed");
                } else {
                    tracing::info!(%peer,"RDP client disconnected");
                }
            }
            incoming = listener.accept() => {
                let (stream, peer) = incoming?;
                if active.load(Ordering::Acquire) || connections.len() >= MAX_PENDING_AUTHENTICATIONS {
                    drop(stream);
                    continue;
                }
                stream.set_nodelay(true)?;
                tracing::info!(%peer,"RDP client connected; authenticating");
                let admission = Arc::new(Admission::new(active.clone()));
                let connection = serve(stream, &settings, frames.clone(), inputs.clone(), fatal.clone(), admission.clone());
                connections.push(Box::pin(async move {
                    (peer, connection.await, admission)
                }));
            }
        }
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
        let mut display = Display::new(rx);
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
        let mut display = Display::new(rx);
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
    #[tokio::test]
    async fn resize_during_negotiation_precedes_first_pixels() {
        let (tx, rx) = watch::channel(Arc::new(Frame::new(640, 480).unwrap()));
        let mut display = Display::new(rx);
        assert_eq!(display.size().await.width, 640);
        tx.send_replace(Arc::new(Frame::new(800, 600).unwrap()));
        // Encoder setup must use the same dimensions as initial negotiation.
        assert_eq!(display.size().await.width, 640);
        let mut updates = display.updates().await.unwrap();
        let Some(DisplayUpdate::Resize(size)) = updates.next_update().await.unwrap() else {
            panic!("resize must precede the new framebuffer")
        };
        assert_eq!((size.width, size.height), (800, 600));
        assert_eq!(display.size().await.width, 800);
        // IronRDP recreates the update stream after resize reactivation.
        let mut reactivated = display.updates().await.unwrap();
        let Some(DisplayUpdate::Bitmap(bitmap)) = reactivated.next_update().await.unwrap() else {
            panic!("reactivation must receive a complete snapshot")
        };
        assert_eq!((bitmap.width.get(), bitmap.height.get()), (800, 600));
    }

    #[tokio::test]
    async fn only_authenticated_winner_can_send_input_or_reset() {
        let active = Arc::new(AtomicBool::new(false));
        let idle = Arc::new(Admission::new(active.clone()));
        let winner = Arc::new(Admission::new(active.clone()));
        let loser = Arc::new(Admission::new(active.clone()));
        let (tx, mut rx) = mpsc::channel(8);
        let fatal = Arc::new(Notify::new());
        let mut handlers: Vec<_> = [&idle, &winner, &loser]
            .into_iter()
            .map(|admission| AdmittedInput {
                admission: admission.clone(),
                handler: Handler::new(tx.clone(), fatal.clone(), false, false),
            })
            .collect();
        handlers[0].keyboard(KeyboardEvent::UnicodePressed(65));
        assert!(!active.load(Ordering::Acquire));
        winner.authenticate();
        loser.authenticate();
        assert!(winner.admitted.load(Ordering::Acquire));
        assert!(!loser.admitted.load(Ordering::Acquire));
        handlers[2].keyboard(KeyboardEvent::UnicodePressed(66));
        handlers[2].mouse(MouseEvent::Move { x: 2, y: 3 });
        idle.finish(&tx).await.unwrap();
        loser.finish(&tx).await.unwrap();
        assert!(rx.try_recv().is_err());
        assert!(active.load(Ordering::Acquire));
        handlers[1].keyboard(KeyboardEvent::UnicodePressed(67));
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Key {
                down: true,
                keysym: 67
            })
        ));
        winner.finish(&tx).await.unwrap();
        assert!(matches!(rx.try_recv(), Ok(Input::Reset)));
        assert!(!active.load(Ordering::Acquire));
        assert!(rx.try_recv().is_err());
        let next = Admission::new(active);
        next.authenticate();
        assert!(next.admitted.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn unsuccessful_contender_cannot_receive_framebuffer() {
        let (_tx, rx) = watch::channel(Arc::new(Frame::new(640, 480).unwrap()));
        let mut display = Display::new(rx);
        let admission = Arc::new(Admission::new(Arc::new(AtomicBool::new(true))));
        display.admission = Some(admission.clone());
        assert!(display.updates().await.is_err());
        admission.authenticate();
        assert!(display.updates().await.is_err());
    }

    #[tokio::test]
    async fn pending_connection_does_not_block_ready_connection() {
        let peer = "127.0.0.1:1".parse().unwrap();
        let admission = Arc::new(Admission::new(Arc::new(AtomicBool::new(false))));
        let mut connections: Vec<Connection<'_>> = vec![
            Box::pin(std::future::pending()),
            Box::pin(async move { (peer, Ok(()), admission) }),
        ];
        let (completed_peer, outcome, _) = completed(&mut connections).await;
        assert_eq!(completed_peer, peer);
        assert!(outcome.is_ok());
        assert_eq!(connections.len(), 1);
    }
}
