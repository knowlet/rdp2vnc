use std::{fs::{self,OpenOptions},io::Write,path::{Path,PathBuf},sync::Arc};
use anyhow::{Result,Context,ensure};
use ironrdp_server::TlsIdentityCtx;
use sha2::{Digest,Sha256};
use tokio_rustls::{TlsAcceptor,rustls};
use crate::config::Args;

fn private_write(path:&Path,bytes:&[u8])->Result<()> {
    let mut options=OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let mut file=options.open(path).with_context(||format!("creating {} (will not overwrite)",path.display()))?;
    file.write_all(bytes)?;file.sync_all()?;Ok(())
}

fn default_identity()->Result<(PathBuf,PathBuf)> {
    let dirs=directories::ProjectDirs::from("", "", "rdp2vnc").context("cannot locate per-user configuration directory; provide --cert and --key")?;
    let dir=dirs.data_local_dir().join("tls");
    fs::create_dir_all(&dir)?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(&dir,fs::Permissions::from_mode(0o700))?;}
    let cert=dir.join("server.pem");let key=dir.join("server-key.pem");
    if cert.exists() || key.exists() {
        ensure!(cert.is_file() && key.is_file(),"incomplete local TLS identity; restore both files or supply --cert and --key");
        return Ok((cert,key));
    }
    let mut params=rcgen::CertificateParams::new(vec!["localhost".into(),"127.0.0.1".into(),"::1".into()])?;
    params.not_before=time::OffsetDateTime::now_utc()-time::Duration::days(1);
    params.not_after=time::OffsetDateTime::now_utc()+time::Duration::days(365);
    params.distinguished_name.push(rcgen::DnType::CommonName,"rdp2vnc local gateway");
    let pair=rcgen::KeyPair::generate()?;
    let certificate=params.self_signed(&pair)?;
    private_write(&key,pair.serialize_pem().as_bytes())?;
    private_write(&cert,certificate.pem().as_bytes())?;
    eprintln!("Created a private, per-user TLS identity in {}",dir.display());
    Ok((cert,key))
}

pub fn identity(args:&Args)->Result<(TlsAcceptor,Vec<u8>)> {
    let (cert,key)=match (&args.cert,&args.key) {
        (Some(cert),Some(key))=>(cert.clone(),key.clone()),(None,None)=>default_identity()?,
        _=>anyhow::bail!("--cert and --key must be provided together"),
    };
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        ensure!(fs::metadata(&key)?.permissions().mode()&0o077==0,"TLS private key must not be group/world accessible; chmod 600 it");
    }
    let identity=TlsIdentityCtx::init_from_paths(&cert,&key).context("loading RDP TLS certificate/key")?;
    let fingerprint=Sha256::digest(identity.certs.first().context("empty certificate chain")?.as_ref());
    let fingerprint=fingerprint.iter().map(|b|format!("{b:02X}")).collect::<Vec<_>>().join(":");
    eprintln!("RDP certificate SHA-256: {fingerprint}");
    // Explicit TLS 1.2/1.3 only. Do not use the helper's make_acceptor(): it
    // enables SSLKEYLOGFILE. Session keys must not be logged by this CLI.
    let config=rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13,&rustls::version::TLS12])
        .with_no_client_auth().with_single_cert(identity.certs,identity.priv_key)
        .context("invalid RDP certificate/key pair")?;
    Ok((TlsAcceptor::from(Arc::new(config)),identity.pub_key))
}

pub fn profile(args:&Args)->Result<()> {
    let Some(path)=&args.rdp_file else{return Ok(());};
    let address=if args.listen.ip().is_unspecified(){
        format!("localhost:{}",args.listen.port())
    }else{args.listen.to_string()};
    let profile=format!("full address:s:{address}\r\nusername:s:{}\r\nenablecredsspsupport:i:1\r\nauthentication level:i:1\r\nredirectclipboard:i:0\r\naudiomode:i:2\r\n",args.rdp_username);
    private_write(path,profile.as_bytes())?;
    eprintln!("Wrote {} (no password); replace localhost with the gateway hostname when connecting remotely.",path.display());
    Ok(())
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn never_overwrites_a_key_or_profile() {
        let dir=tempfile::tempdir().unwrap();let file=dir.path().join("private");
        private_write(&file,b"first").unwrap();assert!(private_write(&file,b"second").is_err());
        assert_eq!(fs::read(&file).unwrap(),b"first");
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;assert_eq!(fs::metadata(&file).unwrap().permissions().mode()&0o777,0o600);}
    }
}
