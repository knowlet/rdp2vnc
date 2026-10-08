//! Bounded RFB 3.3/3.7/3.8 client, including the Apple 3.889 banner.
//! Advertise only encodings that we actually decode. Protocol parsing lives
//! on a dedicated reader; cancellation of a partial message closes the wire.
use crate::{
    auth,
    framebuffer::Frame,
    transport::{BoxWire, Endpoint},
};
use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio_rustls::{TlsConnector, rustls};
use zeroize::Zeroizing;

const MAX_TEXT: usize = 1024 * 1024;
const MAX_COMPRESSED: usize = 32 * 1024 * 1024;
const MAX_INFLATED: usize = 128 * 1024 * 1024;
const ENCODINGS: [i32; 6] = [16, 5, 1, 0, -223, -224];

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum Auth {
    #[default]
    Auto,
    Vnc,
    Ard,
    None,
}

pub struct Options {
    pub auth: Auth,
    pub username: Option<String>,
    pub password: Zeroizing<String>,
    pub allow_insecure: bool,
    pub ca: Option<PathBuf>,
}

#[derive(Debug)]
pub enum Input {
    Key { down: bool, keysym: u32 },
    Pointer { mask: u8, x: u16, y: u16 },
    Reset,
}

pub struct Client {
    stream: BoxWire,
    pub frame: Frame,
    pub apple: bool,
    pub security: &'static str,
    pub name: String,
}

pub fn negotiate_version(banner: &[u8; 12]) -> Result<(u16, bool)> {
    ensure!(
        &banner[..4] == b"RFB " && banner[7] == b'.' && banner[11] == b'\n',
        "invalid RFB banner"
    );
    let major = std::str::from_utf8(&banner[4..7])?.parse::<u16>()?;
    let minor = std::str::from_utf8(&banner[8..11])?.parse::<u16>()?;
    ensure!(major == 3 && minor >= 3, "unsupported RFB version");
    Ok((
        if minor >= 8 {
            8
        } else if minor >= 7 {
            7
        } else {
            3
        },
        minor == 889,
    ))
}

fn choose_auth(types: &[u8], options: &Options) -> Result<u8> {
    let desired = match options.auth {
        Auth::None => 1,
        Auth::Vnc => 2,
        Auth::Ard => 30,
        Auth::Auto => {
            if options.username.is_some() {
                30
            } else {
                2
            }
        }
    };
    ensure!(
        types.contains(&desired),
        "requested VNC authentication is not offered; types={types:?}. Apple ARD requires --username; None requires --auth none"
    );
    Ok(desired)
}

async fn read_text<R: AsyncRead + Unpin>(r: &mut R, limit: usize) -> Result<String> {
    let len = r.read_u32().await? as usize;
    ensure!(len <= limit, "RFB text length exceeds limit");
    let mut bytes = vec![0; len];
    r.read_exact(&mut bytes).await?;
    Ok(String::from_utf8_lossy(&bytes)
        .chars()
        .filter(|c| !c.is_control())
        .collect())
}

async fn result(stream: &mut BoxWire, version: u16) -> Result<()> {
    if stream.read_u32().await? != 0 {
        let reason = if version >= 8 {
            read_text(stream, 4096).await?
        } else {
            "authentication rejected".into()
        };
        bail!("VNC authentication failed: {reason}");
    }
    Ok(())
}

async fn do_auth(stream: &mut BoxWire, kind: u8, options: &Options) -> Result<()> {
    match kind {
        1 => {}
        2 => {
            let mut challenge = [0u8; 16];
            stream.read_exact(&mut challenge).await?;
            let response = auth::vnc_response(options.password.as_bytes(), challenge)?;
            stream.write_all(&response).await?;
        }
        30 => {
            let username = options
                .username
                .as_deref()
                .context("ARD requires --username")?;
            let generator = stream.read_u16().await?;
            let len = usize::from(stream.read_u16().await?);
            ensure!((64..=512).contains(&len), "invalid ARD key length");
            let mut modulus = vec![0; len];
            let mut peer = vec![0; len];
            stream.read_exact(&mut modulus).await?;
            stream.read_exact(&mut peer).await?;
            let response =
                auth::ard_response(generator, &modulus, &peer, username, &options.password)?;
            stream.write_all(&response).await?;
        }
        _ => bail!("unsupported RFB authentication"),
    }
    stream.flush().await?;
    Ok(())
}

async fn vencrypt(mut stream: BoxWire, host: &str, options: &Options) -> Result<(BoxWire, u8)> {
    ensure!(
        stream.read_u8().await? == 0 && stream.read_u8().await? == 2,
        "VeNCrypt 0.2 required"
    );
    stream.write_all(&[0, 2]).await?;
    stream.flush().await?;
    ensure!(stream.read_u8().await? == 0, "VeNCrypt version rejected");
    let count = stream.read_u8().await?;
    ensure!(count > 0 && count <= 64, "invalid VeNCrypt subtype count");
    let mut subtypes = Vec::new();
    for _ in 0..count {
        subtypes.push(stream.read_u32().await?);
    }
    let subtype = match options.auth {
        Auth::None => 260,
        Auth::Vnc => 261,
        Auth::Ard => bail!("ARD cannot be nested in VeNCrypt; use SSH"),
        Auth::Auto => {
            if options.username.is_some() {
                262
            } else {
                261
            }
        }
    };
    ensure!(
        subtypes.contains(&subtype),
        "no compatible authenticated X509 VeNCrypt subtype; anonymous TLS is deliberately unsupported"
    );
    stream.write_u32(subtype).await?;
    stream.flush().await?;
    ensure!(stream.read_u8().await? == 1, "VeNCrypt subtype rejected");
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &options.ca {
        let mut pem = std::io::BufReader::new(
            std::fs::File::open(path).context("opening VNC CA certificate")?,
        );
        let certs = rustls_pemfile::certs(&mut pem).collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "VNC CA file contains no certificates");
        for cert in certs {
            roots.add(cert)?;
        }
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .context("invalid VNC TLS server name")?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .context("VNC TLS validation failed (no insecure certificate fallback)")?;
    let mut stream: BoxWire = Box::new(tls);
    match subtype {
        260 => {}
        261 => do_auth(&mut stream, 2, options).await?,
        262 => {
            let username = options
                .username
                .as_deref()
                .context("X509Plain requires --username")?;
            ensure!(
                username.len() <= 1024 && options.password.len() <= 1024,
                "VeNCrypt credential too long"
            );
            stream.write_u32(username.len() as u32).await?;
            stream.write_u32(options.password.len() as u32).await?;
            stream.write_all(username.as_bytes()).await?;
            stream.write_all(options.password.as_bytes()).await?;
        }
        _ => unreachable!(),
    }
    stream.flush().await?;
    Ok((stream, if subtype == 260 { 1 } else { 2 }))
}

impl Client {
    pub async fn handshake(
        mut stream: BoxWire,
        target: &Endpoint,
        protected: bool,
        options: &Options,
    ) -> Result<Self> {
        let mut banner = [0; 12];
        stream.read_exact(&mut banner).await?;
        let (version, mut apple) = negotiate_version(&banner)?;
        stream
            .write_all(format!("RFB 003.{version:03}\n").as_bytes())
            .await?;
        stream.flush().await?;
        let types = if version == 3 {
            let kind = stream.read_u32().await?;
            if kind == 0 {
                bail!(
                    "VNC server rejected connection: {}",
                    read_text(&mut stream, 4096).await?
                );
            }
            ensure!(kind <= 255, "unknown legacy RFB security type");
            vec![kind as u8]
        } else {
            let n = stream.read_u8().await?;
            if n == 0 {
                bail!(
                    "VNC server rejected connection: {}",
                    read_text(&mut stream, 4096).await?
                );
            }
            let mut types = vec![0; usize::from(n)];
            stream.read_exact(&mut types).await?;
            types
        };
        // A CA file is an explicit TLS policy, never silently bypass it.
        let tls = types.contains(&19)
            && (!protected || options.ca.is_some())
            && options.auth != Auth::Ard;
        ensure!(
            options.ca.is_none() || tls,
            "VNC CA configured but VeNCrypt is unavailable"
        );
        ensure!(
            protected || tls || options.allow_insecure,
            "VNC would be unencrypted. Use --ssh user@host with target 127.0.0.1, X509 VeNCrypt, or explicitly --allow-insecure-vnc for a trusted VPN/LAN"
        );
        let kind = if tls {
            19
        } else {
            choose_auth(&types, options)?
        };
        if version != 3 {
            stream.write_u8(kind).await?;
            stream.flush().await?;
        }
        let security = if tls {
            (stream, _) = vencrypt(stream, &target.host, options).await?;
            result(&mut stream, version).await?;
            "VeNCrypt X509/TLS"
        } else {
            do_auth(&mut stream, kind, options).await?;
            if kind != 1 || version >= 8 {
                result(&mut stream, version).await?;
            }
            apple |= kind == 30;
            if protected {
                "SSH/loopback"
            } else {
                "UNENCRYPTED (explicit opt-in)"
            }
        };
        stream.write_u8(1).await?;
        stream.flush().await?; // Shared desktop, never exclusive.
        let width = stream.read_u16().await?;
        let height = stream.read_u16().await?;
        let mut server_format = [0; 16];
        stream.read_exact(&mut server_format).await?;
        let name = read_text(&mut stream, 65536).await?;
        let frame = Frame::new(width, height)?;
        // 32 bpp, depth 24, little endian, true colour, R16/G8/B0 => BGRX bytes.
        stream
            .write_all(&[
                0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0,
            ])
            .await?;
        stream.write_u8(2).await?;
        stream.write_u8(0).await?;
        stream.write_u16(ENCODINGS.len() as u16).await?;
        for encoding in ENCODINGS {
            stream.write_i32(encoding).await?;
        }
        refresh(&mut stream, false, width, height).await?;
        Ok(Self {
            stream,
            frame,
            apple,
            security,
            name,
        })
    }

    pub async fn run(
        self,
        frames: watch::Sender<Arc<Frame>>,
        inputs: mpsc::Receiver<Input>,
        fps: u16,
    ) -> Result<()> {
        ensure!((1..=60).contains(&fps), "fps must be 1..60");
        let (reader, writer) = tokio::io::split(self.stream);
        let (requests, request_rx) = mpsc::channel(1);
        let read = read_frames(reader, self.frame, frames, requests, fps);
        let write = write_inputs(writer, inputs, request_rx);
        tokio::pin!(read, write);
        tokio::select! {result=&mut read=>result,result=&mut write=>result}
    }
}

async fn refresh<W: AsyncWrite + Unpin>(
    w: &mut W,
    incremental: bool,
    width: u16,
    height: u16,
) -> Result<()> {
    w.write_all(&[3, u8::from(incremental), 0, 0, 0, 0]).await?;
    w.write_u16(width).await?;
    w.write_u16(height).await?;
    w.flush().await?;
    Ok(())
}
async fn key<W: AsyncWrite + Unpin>(w: &mut W, down: bool, keysym: u32) -> Result<()> {
    w.write_all(&[4, u8::from(down), 0, 0]).await?;
    w.write_u32(keysym).await?;
    Ok(())
}
async fn pointer<W: AsyncWrite + Unpin>(w: &mut W, mask: u8, x: u16, y: u16) -> Result<()> {
    w.write_all(&[5, mask]).await?;
    w.write_u16(x).await?;
    w.write_u16(y).await?;
    Ok(())
}
async fn write_inputs<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut input: mpsc::Receiver<Input>,
    mut requests: mpsc::Receiver<(bool, u16, u16)>,
) -> Result<()> {
    let mut pressed = BTreeSet::new();
    let mut position = (0, 0);
    loop {
        enum Event {
            Input(Input),
            Refresh(bool, u16, u16),
        }
        let event = tokio::select! {
            event=input.recv()=>match event{Some(e)=>Event::Input(e),None=>return Ok(())},
            request=requests.recv()=>match request{Some((i,w,h))=>Event::Refresh(i,w,h),None=>return Ok(())},
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            match event {
                Event::Refresh(i, w, h) => refresh(&mut writer, i, w, h).await?,
                Event::Input(Input::Key { down, keysym }) => {
                    if down {
                        ensure!(
                            pressed.len() < 256 || pressed.contains(&keysym),
                            "too many pressed keys"
                        );
                        pressed.insert(keysym);
                    } else {
                        pressed.remove(&keysym);
                    }
                    key(&mut writer, down, keysym).await?;
                }
                Event::Input(Input::Pointer { mask, x, y }) => {
                    position = (x, y);
                    pointer(&mut writer, mask, x, y).await?;
                }
                Event::Input(Input::Reset) => {
                    for keysym in std::mem::take(&mut pressed) {
                        key(&mut writer, false, keysym).await?;
                    }
                    pointer(&mut writer, 0, position.0, position.1).await?;
                }
            }
            writer.flush().await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("VNC writer timed out")??;
    }
}

async fn pixel<R: AsyncRead + Unpin>(r: &mut R) -> Result<[u8; 4]> {
    let mut p = [0; 4];
    r.read_exact(&mut p).await?;
    Ok(p)
}

async fn hextile<R: AsyncRead + Unpin>(
    r: &mut R,
    frame: &mut Frame,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
) -> Result<()> {
    frame.check_rect(x, y, w, h)?;
    let mut background = None;
    let mut foreground = None;
    for ty in (0..h).step_by(16) {
        for tx in (0..w).step_by(16) {
            let tw = (w - tx).min(16);
            let th = (h - ty).min(16);
            let flags = r.read_u8().await?;
            ensure!(flags & !31 == 0, "invalid Hextile flags");
            if flags & 1 != 0 {
                let mut raw = vec![0; usize::from(tw) * usize::from(th) * 4];
                r.read_exact(&mut raw).await?;
                frame.put(x + tx, y + ty, tw, th, &raw)?;
                continue;
            }
            if flags & 2 != 0 {
                background = Some(pixel(r).await?);
            }
            if flags & 4 != 0 {
                foreground = Some(pixel(r).await?);
            }
            frame.fill(
                x + tx,
                y + ty,
                tw,
                th,
                background.context("Hextile has no background colour")?,
            )?;
            if flags & 8 != 0 {
                let n = r.read_u8().await?;
                for _ in 0..n {
                    let p = if flags & 16 != 0 {
                        pixel(r).await?
                    } else {
                        foreground.context("Hextile has no foreground colour")?
                    };
                    let xy = r.read_u8().await?;
                    let wh = r.read_u8().await?;
                    let sx = u16::from(xy >> 4);
                    let sy = u16::from(xy & 15);
                    let sw = u16::from(wh >> 4) + 1;
                    let sh = u16::from(wh & 15) + 1;
                    ensure!(
                        sx + sw <= tw && sy + sh <= th,
                        "Hextile subrectangle outside tile"
                    );
                    frame.fill(x + tx + sx, y + ty + sy, sw, sh, p)?;
                }
            }
        }
    }
    Ok(())
}

struct Slice<'a>(&'a [u8]);
impl Slice<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(n <= self.0.len(), "truncated ZRLE tile");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn pixel(&mut self) -> Result<[u8; 4]> {
        let p = self.take(3)?;
        Ok([p[0], p[1], p[2], 0])
    }
    fn run(&mut self, remaining: usize) -> Result<usize> {
        let mut n = 1;
        loop {
            let b = self.byte()?;
            n += usize::from(b);
            ensure!(n <= remaining, "ZRLE run exceeds tile");
            if b != 255 {
                return Ok(n);
            }
        }
    }
}

fn zrle(frame: &mut Frame, x: u16, y: u16, w: u16, h: u16, decoded: &[u8]) -> Result<()> {
    frame.check_rect(x, y, w, h)?;
    let mut data = Slice(decoded);
    for ty in (0..h).step_by(64) {
        for tx in (0..w).step_by(64) {
            let tw = (w - tx).min(64);
            let th = (h - ty).min(64);
            let count = usize::from(tw) * usize::from(th);
            let kind = data.byte()?;
            let palette_len = usize::from(kind & 127);
            ensure!(
                kind >= 128 || palette_len <= 16,
                "invalid ZRLE palette encoding"
            );
            let mut palette = Vec::with_capacity(palette_len);
            for _ in 0..palette_len {
                palette.push(data.pixel()?);
            }
            let mut pixels = Vec::with_capacity(count * 4);
            match kind {
                0 => {
                    for _ in 0..count {
                        pixels.extend(data.pixel()?);
                    }
                }
                1 => {
                    for _ in 0..count {
                        pixels.extend(palette[0]);
                    }
                }
                2..=16 => {
                    let bits = if palette_len <= 2 {
                        1
                    } else if palette_len <= 4 {
                        2
                    } else {
                        4
                    };
                    for _ in 0..th {
                        let mut packed = 0;
                        let mut left = 0;
                        for _ in 0..tw {
                            if left == 0 {
                                packed = data.byte()?;
                                left = 8;
                            }
                            left -= bits;
                            let i = usize::from((packed >> left) & ((1 << bits) - 1));
                            pixels.extend(*palette.get(i).context("invalid ZRLE palette index")?);
                        }
                    }
                }
                128 => {
                    while pixels.len() / 4 < count {
                        let p = data.pixel()?;
                        let n = data.run(count - pixels.len() / 4)?;
                        for _ in 0..n {
                            pixels.extend(p);
                        }
                    }
                }
                129..=255 => {
                    while pixels.len() / 4 < count {
                        let index = data.byte()?;
                        let p = *palette
                            .get(usize::from(index & 127))
                            .context("invalid ZRLE RLE palette index")?;
                        let n = if index & 128 != 0 {
                            data.run(count - pixels.len() / 4)?
                        } else {
                            1
                        };
                        for _ in 0..n {
                            pixels.extend(p);
                        }
                    }
                }
                _ => bail!("invalid ZRLE tile"),
            }
            frame.put(x + tx, y + ty, tw, th, &pixels)?;
        }
    }
    ensure!(data.0.is_empty(), "trailing bytes in ZRLE rectangle");
    Ok(())
}

fn inflate(inflater: &mut flate2::Decompress, input: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut offset = 0;
    loop {
        ensure!(output.len() < limit, "ZRLE inflated data exceeds limit");
        let mut chunk = [0u8; 32768];
        let available = (limit - output.len()).min(chunk.len());
        let before_in = inflater.total_in();
        let before_out = inflater.total_out();
        let status = inflater.decompress(
            &input[offset..],
            &mut chunk[..available],
            flate2::FlushDecompress::Sync,
        )?;
        let consumed = (inflater.total_in() - before_in) as usize;
        let produced = (inflater.total_out() - before_out) as usize;
        offset += consumed;
        output.extend_from_slice(&chunk[..produced]);
        if status == flate2::Status::StreamEnd {
            ensure!(offset == input.len(), "trailing compressed data");
            inflater.reset(true);
            return Ok(output);
        }
        if offset == input.len() && produced < available {
            return Ok(output);
        }
        ensure!(
            consumed != 0 || produced != 0,
            "invalid or stalled ZRLE stream"
        );
    }
}

async fn read_frames<R: AsyncRead + Unpin>(
    mut r: R,
    mut frame: Frame,
    frames: watch::Sender<Arc<Frame>>,
    requests: mpsc::Sender<(bool, u16, u16)>,
    fps: u16,
) -> Result<()> {
    let mut inflater = flate2::Decompress::new(true);
    loop {
        match r
            .read_u8()
            .await
            .context("VNC disconnected while reading a message")?
        {
            0 => {
                r.read_u8().await?;
                let count = r.read_u16().await?;
                ensure!(
                    count <= 4096 || count == 65535,
                    "too many framebuffer rectangles"
                );
                let mut last = false;
                let mut resized = false;
                for index in 0..count {
                    ensure!(index < 4096, "LastRect update exceeds rectangle budget");
                    let x = r.read_u16().await?;
                    let y = r.read_u16().await?;
                    let w = r.read_u16().await?;
                    let h = r.read_u16().await?;
                    let encoding = r.read_i32().await?;
                    match encoding {
                        -224 => {
                            last = true;
                            break;
                        }
                        -223 => {
                            frame = Frame::new(w, h)?;
                            resized = true;
                        }
                        0 => {
                            frame.check_rect(x, y, w, h)?;
                            let mut bytes = vec![0; usize::from(w) * usize::from(h) * 4];
                            r.read_exact(&mut bytes).await?;
                            frame.put(x, y, w, h, &bytes)?;
                        }
                        1 => {
                            let sx = r.read_u16().await?;
                            let sy = r.read_u16().await?;
                            frame.copy_rect(sx, sy, x, y, w, h)?;
                        }
                        5 => hextile(&mut r, &mut frame, x, y, w, h).await?,
                        16 => {
                            frame.check_rect(x, y, w, h)?;
                            let len = r.read_u32().await? as usize;
                            ensure!(
                                len > 0 && len <= MAX_COMPRESSED,
                                "invalid ZRLE compressed length"
                            );
                            let mut compressed = vec![0; len];
                            r.read_exact(&mut compressed).await?;
                            let budget = (usize::from(w) * usize::from(h) * 5
                                + usize::from(w.div_ceil(64)) * usize::from(h.div_ceil(64)) * 400
                                + 1)
                            .min(MAX_INFLATED);
                            let decoded = inflate(&mut inflater, &compressed, budget)?;
                            zrle(&mut frame, x, y, w, h, &decoded)?;
                        }
                        _ => bail!(
                            "server sent an unadvertised encoding {encoding}; cannot safely skip an unknown payload"
                        ),
                    }
                }
                ensure!(count != 65535 || last, "missing LastRect marker");
                if count > 0 {
                    frames.send_replace(Arc::new(frame.clone()));
                }
                tokio::time::sleep(Duration::from_secs_f64(1.0 / f64::from(fps))).await;
                requests
                    .send((!resized, frame.width, frame.height))
                    .await
                    .context("VNC writer stopped")?;
            }
            1 => {
                r.read_u8().await?;
                let _first = r.read_u16().await?;
                let n = r.read_u16().await?;
                ensure!(n <= 256, "oversized colour map");
                let mut discard = vec![0; usize::from(n) * 6];
                r.read_exact(&mut discard).await?;
            }
            2 => {} // Bell, not an audio stream.
            3 => {
                let mut padding = [0; 3];
                r.read_exact(&mut padding).await?;
                let _ = read_text(&mut r, MAX_TEXT).await?;
            }
            message => bail!("unsupported RFB server message {message}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions_include_apple_but_do_not_force_legacy() {
        assert_eq!(negotiate_version(b"RFB 003.889\n").unwrap(), (8, true));
        assert_eq!(negotiate_version(b"RFB 003.003\n").unwrap(), (3, false));
        assert_eq!(negotiate_version(b"RFB 003.007\n").unwrap(), (7, false));
        assert!(negotiate_version(b"RFB 004.008\n").is_err());
    }
    #[test]
    fn authentication_never_downgrades_to_none() {
        let options = Options {
            auth: Auth::Auto,
            username: None,
            password: Zeroizing::new("a".into()),
            allow_insecure: false,
            ca: None,
        };
        assert!(choose_auth(&[1], &options).is_err());
        assert_eq!(choose_auth(&[1, 2], &options).unwrap(), 2);
    }
    #[test]
    fn zrle_solid_and_raw_tiles() {
        let mut f = Frame::new(2, 1).unwrap();
        zrle(&mut f, 0, 0, 2, 1, &[1, 10, 20, 30]).unwrap();
        assert_eq!(f.pixels, [10, 20, 30, 0, 10, 20, 30, 0]);
        zrle(&mut f, 0, 0, 2, 1, &[0, 1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(f.pixels, [1, 2, 3, 0, 4, 5, 6, 0]);
    }
    #[test]
    fn zrle_rejects_overruns_and_truncated_palette() {
        let mut f = Frame::new(2, 1).unwrap();
        assert!(zrle(&mut f, 0, 0, 2, 1, &[128, 1, 2, 3, 8]).is_err());
        assert!(zrle(&mut f, 0, 0, 2, 1, &[2, 1]).is_err());
    }
    #[tokio::test]
    async fn fragmented_handshake_and_raw_update() {
        let (client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            for b in b"RFB 003.889\n" {
                server.write_all(&[*b]).await.unwrap();
                tokio::task::yield_now().await;
            }
            let mut version = [0; 12];
            server.read_exact(&mut version).await.unwrap();
            assert_eq!(&version, b"RFB 003.008\n");
            server.write_all(&[1, 1]).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 1);
            server.write_u32(0).await.unwrap();
            assert_eq!(server.read_u8().await.unwrap(), 1);
            server.write_u16(2).await.unwrap();
            server.write_u16(1).await.unwrap();
            server.write_all(&[0; 16]).await.unwrap();
            server.write_u32(4).await.unwrap();
            server.write_all(b"test").await.unwrap();
            let mut setup = vec![0; 20 + 4 + ENCODINGS.len() * 4 + 10];
            server.read_exact(&mut setup).await.unwrap();
            server.write_all(&[0, 0, 0, 1]).await.unwrap();
            for v in [0, 0, 2, 1] {
                server.write_u16(v).await.unwrap();
            }
            server.write_i32(0).await.unwrap();
            server.write_all(&[1, 2, 3, 0, 4, 5, 6, 0]).await.unwrap();
            let mut refresh = [0; 10];
            server.read_exact(&mut refresh).await.unwrap();
        });
        let options = Options {
            auth: Auth::None,
            username: None,
            password: Zeroizing::new(String::new()),
            allow_insecure: false,
            ca: None,
        };
        let client = Client::handshake(
            Box::new(client),
            &"localhost".parse().unwrap(),
            true,
            &options,
        )
        .await
        .unwrap();
        assert!(client.apple);
        let (tx, mut rx) = watch::channel(Arc::new(client.frame.clone()));
        let (_input_tx, input_rx) = mpsc::channel(8);
        let task = tokio::spawn(client.run(tx, input_rx, 60));
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.borrow().pixels, [1, 2, 3, 0, 4, 5, 6, 0]);
        server_task.await.unwrap();
        let _ = task.await;
    }
}
