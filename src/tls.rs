use crate::config::Args;
use anyhow::{Context, Result, ensure};
use ironrdp_server::TlsIdentityCtx;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_rustls::{TlsAcceptor, rustls};

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {} (will not overwrite)", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn default_identity() -> Result<(PathBuf, PathBuf)> {
    let dirs = directories::ProjectDirs::from("", "", "rdp2vnc")
        .context("cannot locate per-user configuration directory; provide --cert and --key")?;
    default_identity_in(&dirs.data_local_dir().join("tls"), private_write)
}

// Only a complete identity is published. Interrupted staging directories are
// ignored, while an existing (including legacy) identity is never regenerated.
fn default_identity_in(
    dir: &Path,
    write: impl Fn(&Path, &[u8]) -> Result<()>,
) -> Result<(PathBuf, PathBuf)> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let legacy_cert = dir.join("server.pem");
    let legacy_key = dir.join("server-key.pem");
    if legacy_cert.symlink_metadata().is_ok() || legacy_key.symlink_metadata().is_ok() {
        return existing_identity(dir);
    }
    let published = dir.join("identity");
    if published.symlink_metadata().is_ok() {
        return existing_identity(&published);
    }

    let mut random = [0; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| anyhow::anyhow!("creating TLS staging directory name: {error}"))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let staging = dir.join(format!(".identity-{suffix}"));
    // Do not remove a pre-existing path if creation fails.
    let builder = &mut fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&staging)?;
    let staging = StagedIdentity(staging);
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into(), "::1".into()])?;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rdp2vnc local gateway");
    let pair = rcgen::KeyPair::generate()?;
    let certificate = params.self_signed(&pair)?;
    write(
        &staging.0.join("server-key.pem"),
        pair.serialize_pem().as_bytes(),
    )?;
    write(&staging.0.join("server.pem"), certificate.pem().as_bytes())?;
    #[cfg(unix)]
    fs::File::open(&staging.0)?.sync_all()?;
    if let Err(error) = fs::rename(&staging.0, &published) {
        // A concurrent initializer can win. A populated directory cannot be
        // overwritten by rename; use the winner without mixing either pair.
        if published.is_dir() {
            return existing_identity(&published);
        }
        return Err(error).context("publishing local TLS identity");
    }
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    eprintln!(
        "Created a private, per-user TLS identity in {}",
        dir.display()
    );
    existing_identity(&published)
}

fn existing_identity(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let cert = dir.join("server.pem");
    let key = dir.join("server-key.pem");
    ensure!(
        cert.is_file() && key.is_file(),
        "incomplete local TLS identity in {}; restore both files or supply --cert and --key",
        dir.display()
    );
    Ok((cert, key))
}

struct StagedIdentity(PathBuf);

impl Drop for StagedIdentity {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn identity(args: &Args) -> Result<(TlsAcceptor, Vec<u8>)> {
    let (cert, key) = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => (cert.clone(), key.clone()),
        (None, None) => default_identity()?,
        _ => anyhow::bail!("--cert and --key must be provided together"),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            fs::metadata(&key)?.permissions().mode() & 0o077 == 0,
            "TLS private key must not be group/world accessible; chmod 600 it"
        );
    }
    let identity =
        TlsIdentityCtx::init_from_paths(&cert, &key).context("loading RDP TLS certificate/key")?;
    let fingerprint = Sha256::digest(
        identity
            .certs
            .first()
            .context("empty certificate chain")?
            .as_ref(),
    );
    let fingerprint = fingerprint
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    eprintln!("RDP certificate SHA-256: {fingerprint}");
    // Explicit TLS 1.2/1.3 only. Do not use the helper's make_acceptor(): it
    // enables SSLKEYLOGFILE. Session keys must not be logged by this CLI.
    let config = rustls::ServerConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS13,
        &rustls::version::TLS12,
    ])
    .with_no_client_auth()
    .with_single_cert(identity.certs, identity.priv_key)
    .context("invalid RDP certificate/key pair")?;
    Ok((TlsAcceptor::from(Arc::new(config)), identity.pub_key))
}

pub fn profile(args: &Args) -> Result<()> {
    let Some(path) = &args.rdp_file else {
        return Ok(());
    };
    let address = if args.listen.ip().is_unspecified() {
        format!("localhost:{}", args.listen.port())
    } else {
        args.listen.to_string()
    };
    let profile = format!(
        "full address:s:{address}\r\nusername:s:{}\r\nenablecredsspsupport:i:1\r\nauthentication level:i:1\r\nredirectclipboard:i:0\r\naudiomode:i:2\r\n",
        args.rdp_username
    );
    private_write(path, profile.as_bytes())?;
    eprintln!(
        "Wrote {} (no password); replace localhost with the gateway hostname when connecting remotely.",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn assert_valid_identity(cert: &Path, key: &Path) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut args = Args::parse_from(["rdp2vnc"]);
        args.cert = Some(cert.to_path_buf());
        args.key = Some(key.to_path_buf());
        let (acceptor, _) = identity(&args).unwrap();
        for label in [
            "CLIENT_RANDOM",
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET",
        ] {
            assert!(!acceptor.config().key_log.will_log(label));
        }
    }

    #[test]
    fn failed_certificate_write_can_retry_without_partial_identity() {
        let dir = tempfile::tempdir().unwrap();
        let result = default_identity_in(dir.path(), |path, bytes| {
            if path.file_name().unwrap() == "server.pem" {
                // Include a partial write, rather than only a failure to open.
                private_write(path, b"partial certificate")?;
                anyhow::bail!("simulated disk write failure");
            }
            private_write(path, bytes)
        });
        assert!(result.is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        let (cert, key) = default_identity_in(dir.path(), private_write).unwrap();
        assert_valid_identity(&cert, &key);
    }

    #[test]
    fn abandoned_staging_is_ignored_and_published_identity_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let abandoned = dir.path().join(".identity-interrupted");
        fs::create_dir(&abandoned).unwrap();
        private_write(&abandoned.join("server-key.pem"), b"partial key").unwrap();
        let paths = default_identity_in(dir.path(), private_write).unwrap();
        let original_cert = fs::read(&paths.0).unwrap();
        let original_key = fs::read(&paths.1).unwrap();
        assert_valid_identity(&paths.0, &paths.1);
        assert_eq!(
            default_identity_in(dir.path(), |_, _| panic!("must reuse identity")).unwrap(),
            paths
        );
        assert_eq!(fs::read(&paths.0).unwrap(), original_cert);
        assert_eq!(fs::read(&paths.1).unwrap(), original_key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(paths.0.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(paths.1).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn concurrent_initializers_publish_one_matching_pair() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = dir.path().to_path_buf();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    default_identity_in(&path, |path, bytes| {
                        private_write(path, bytes)?;
                        if path.file_name().unwrap() == "server.pem" {
                            barrier.wait();
                        }
                        Ok(())
                    })
                    .unwrap()
                })
            })
            .collect();
        let paths: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(paths[0], paths[1]);
        assert_valid_identity(&paths[0].0, &paths[0].1);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn legacy_identity_is_preserved_and_incomplete_identity_is_not_rotated() {
        let source = tempfile::tempdir().unwrap();
        let (cert, key) = default_identity_in(source.path(), private_write).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let legacy_cert = dir.path().join("server.pem");
        let legacy_key = dir.path().join("server-key.pem");
        private_write(&legacy_key, &fs::read(&key).unwrap()).unwrap();
        assert!(default_identity_in(dir.path(), private_write).is_err());
        assert_eq!(fs::read(&legacy_key).unwrap(), fs::read(&key).unwrap());
        assert!(!dir.path().join("identity").exists());
        private_write(&legacy_cert, &fs::read(&cert).unwrap()).unwrap();
        assert_eq!(
            default_identity_in(dir.path(), private_write).unwrap(),
            (legacy_cert.clone(), legacy_key.clone())
        );
        assert_valid_identity(&legacy_cert, &legacy_key);
        fs::remove_file(&legacy_key).unwrap();
        assert!(default_identity_in(dir.path(), private_write).is_err());
        assert_eq!(fs::read(legacy_cert).unwrap(), fs::read(cert).unwrap());
    }

    #[test]
    fn damaged_published_identity_is_not_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = default_identity_in(dir.path(), private_write).unwrap();
        let original_key = fs::read(&key).unwrap();
        fs::write(&cert, b"damaged certificate").unwrap();
        let paths = default_identity_in(dir.path(), |_, _| panic!("must not rotate")).unwrap();
        assert_eq!(paths, (cert.clone(), key.clone()));
        assert!(TlsIdentityCtx::init_from_paths(&cert, &key).is_err());
        assert_eq!(fs::read(&key).unwrap(), original_key);
        fs::remove_file(&cert).unwrap();
        assert!(default_identity_in(dir.path(), private_write).is_err());
        assert_eq!(fs::read(key).unwrap(), original_key);
    }

    #[test]
    fn profile_requires_server_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = Args::parse_from(["rdp2vnc"]);
        let path = dir.path().join("gateway.rdp");
        args.rdp_file = Some(path.clone());
        profile(&args).unwrap();
        let text = fs::read_to_string(path).unwrap();
        assert!(text.lines().any(|line| line == "authentication level:i:1"));
        assert!(text.lines().any(|line| line == "enablecredsspsupport:i:1"));
        assert!(!text.to_ascii_lowercase().contains("password"));
    }

    #[test]
    fn never_overwrites_a_key_or_profile() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("private");
        private_write(&file, b"first").unwrap();
        assert!(private_write(&file, b"second").is_err());
        assert_eq!(fs::read(&file).unwrap(), b"first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
