use std::{net::IpAddr, pin::Pin, process::Stdio, str::FromStr, task::{Context,Poll}};
use anyhow::{Result,Context as _,ensure};
use tokio::{io::{AsyncRead,AsyncWrite,ReadBuf}, net::TcpStream, process::{Child,ChildStdin,ChildStdout,Command}};

pub trait Wire: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T:AsyncRead+AsyncWrite+Send+Unpin> Wire for T {}
pub type BoxWire = Box<dyn Wire>;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Endpoint { pub host:String, pub port:u16 }
impl Endpoint {
    pub fn authority(&self)->String {
        if self.host.contains(':') {format!("[{}]:{}",self.host,self.port)} else {format!("{}:{}",self.host,self.port)}
    }
    pub fn is_loopback_name(&self)->bool {
        self.host.eq_ignore_ascii_case("localhost") || self.host.parse::<IpAddr>().is_ok_and(|ip|ip.is_loopback())
    }
}
impl FromStr for Endpoint {
    type Err=anyhow::Error;
    fn from_str(value:&str)->Result<Self> {
        let value=value.strip_prefix("vnc://").unwrap_or(value);
        ensure!(!value.is_empty() && !value.chars().any(|c|c.is_control() || c.is_whitespace())
            && !value.contains(['@','/','?','#']), "target must be host[:port] or [IPv6]:port, without credentials or a path");
        let (host,port)=if let Some(rest)=value.strip_prefix('[') {
            let (host,tail)=rest.split_once(']').context("missing IPv6 closing bracket")?;
            ensure!(host.parse::<std::net::Ipv6Addr>().is_ok(),"invalid IPv6 address");
            let port=if tail.is_empty(){5900}else{tail.strip_prefix(':').context("unexpected text after IPv6")?.parse()?};
            (host.to_owned(),port)
        } else if value.parse::<std::net::Ipv6Addr>().is_ok() {
            (value.to_owned(),5900)
        } else if let Some((host,port))=value.rsplit_once(':') {
            ensure!(!host.contains(':'),"bracket an IPv6 address when specifying a port");
            (host.to_owned(),port.parse()?)
        } else {(value.to_owned(),5900)};
        ensure!(!host.is_empty() && !host.starts_with('-') && port!=0,"invalid target host or port");
        Ok(Self{host,port})
    }
}

struct SshWire { _child:Child, stdin:ChildStdin, stdout:ChildStdout }
impl AsyncRead for SshWire {
    fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx,buf)
    }
}
impl AsyncWrite for SshWire {
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx,buf)
    }
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<()>> {Pin::new(&mut self.stdin).poll_flush(cx)}
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<std::io::Result<()>> {Pin::new(&mut self.stdin).poll_shutdown(cx)}
}

/// Returns whether the entire VNC leg is protected (or stays on loopback).
/// SSH forwards only to loopback on its host, so there is no plaintext final hop.
pub async fn connect(target:&Endpoint,ssh:Option<&str>,ssh_port:u16)->Result<(BoxWire,bool)> {
    if let Some(destination)=ssh {
        ensure!(target.is_loopback_name(),"with --ssh, use a loopback VNC target, e.g. 127.0.0.1:5900; SSH must terminate on the VNC host");
        ensure!(!destination.is_empty() && !destination.starts_with('-') &&
            destination.chars().all(|c|c.is_ascii_alphanumeric() || "@._-:[]".contains(c)),"invalid SSH destination");
        let mut child=Command::new("ssh")
            .args(["-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","ExitOnForwardFailure=yes",
                "-o","ConnectTimeout=10","-o","ServerAliveInterval=15","-o","ServerAliveCountMax=3","-p"])
            .arg(ssh_port.to_string()).arg("-W").arg(target.authority()).arg("--").arg(destination)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).kill_on_drop(true)
            .spawn().context("starting OpenSSH (install ssh and enroll the host key first)")?;
        let stdin=child.stdin.take().context("missing SSH stdin")?;
        let stdout=child.stdout.take().context("missing SSH stdout")?;
        return Ok((Box::new(SshWire{_child:child,stdin,stdout}),true));
    }
    let socket=tokio::time::timeout(std::time::Duration::from_secs(10),
        TcpStream::connect((target.host.as_str(),target.port))).await.context("VNC TCP connection timed out")??;
    socket.set_nodelay(true)?;
    let protected=socket.peer_addr()?.ip().is_loopback();
    Ok((Box::new(socket),protected))
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn endpoints() {
        assert_eq!("mac.local".parse::<Endpoint>().unwrap().authority(),"mac.local:5900");
        assert_eq!("vnc://[::1]:5901".parse::<Endpoint>().unwrap().authority(),"[::1]:5901");
        assert!("::1".parse::<Endpoint>().unwrap().is_loopback_name());
        for value in ["","a:0","a:65536","[::1","vnc://user:password@host","host/path","-oProxyCommand=x","host\n"] {
            assert!(value.parse::<Endpoint>().is_err(),"{value}");
        }
    }
    #[tokio::test] async fn ssh_never_silently_leaves_a_plaintext_last_hop() {
        let target="192.0.2.1".parse().unwrap();
        assert!(connect(&target,Some("user@gateway"),22).await.is_err());
    }
}
