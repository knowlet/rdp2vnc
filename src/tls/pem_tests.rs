//! Preserve the unchanged IronRDP identity loader and key-matching policy.
use super::*;
use clap::Parser;

fn certificate() -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.pem(), key.serialize_pem())
}

fn args(dir: &Path, cert_name: &str, key_name: &str, cert: &[u8], key: &[u8]) -> Args {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut args = Args::parse_from(["rdp2vnc"]);
    let cert_path = dir.join(cert_name);
    let key_path = dir.join(key_name);
    private_write(&cert_path, cert).unwrap();
    private_write(&key_path, key).unwrap();
    args.cert = Some(cert_path);
    args.key = Some(key_path);
    args
}

#[test]
fn pem_identity_and_legacy_extensions_preserve_certificate_and_key() {
    let (cert, key) = certificate();
    for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
        let dir = tempfile::tempdir().unwrap();
        let args = args(
            dir.path(),
            cert_name,
            key_name,
            cert.as_bytes(),
            key.as_bytes(),
        );
        let (acceptor, public_key) = identity(&args).unwrap();
        assert!(!public_key.is_empty());
        assert!(!acceptor.config().key_log.will_log("CLIENT_RANDOM"));
        assert_eq!(identity(&args).unwrap().1, public_key);
        assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
        assert_eq!(fs::read(args.key.unwrap()).unwrap(), key.as_bytes());
    }
}

#[test]
fn pem_identity_rejects_empty_damaged_certificates_without_rotation() {
    let (_, key) = certificate();
    for cert in [
        "",
        " \r\n\t",
        "damaged certificate",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let args = args(
            dir.path(),
            "server.pem",
            "key.pem",
            cert.as_bytes(),
            key.as_bytes(),
        );
        assert!(identity(&args).is_err());
        assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
        assert_eq!(fs::read(args.key.unwrap()).unwrap(), key.as_bytes());
    }
}

#[test]
fn pem_identity_rejects_empty_damaged_or_mismatched_keys_without_rotation() {
    let (cert, _) = certificate();
    let (_, different_key) = certificate();
    for key in [
        "",
        " \r\n\t",
        "damaged key",
        "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
        "-----BEGIN PRIVATE KEY-----\nAQID\n",
        "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
        cert.as_str(),
        different_key.as_str(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let args = args(
            dir.path(),
            "server.pem",
            "key.pem",
            cert.as_bytes(),
            key.as_bytes(),
        );
        assert!(identity(&args).is_err());
        assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
        assert_eq!(fs::read(args.key.unwrap()).unwrap(), key.as_bytes());
    }
}
