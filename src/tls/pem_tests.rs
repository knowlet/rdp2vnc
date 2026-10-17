//! Preserve the unchanged IronRDP identity loader and key-matching policy.
use super::*;
use clap::Parser;

fn generated_certificate() -> (rcgen::Certificate, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert, key)
}

fn certificate() -> (String, String, Vec<u8>) {
    let (cert, key) = generated_certificate();
    // The self-signed certificate embeds this raw public key as its subject key.
    // Derive the expected value from the generator, not the production loader.
    (
        cert.pem(),
        key.serialize_pem(),
        key.public_key_raw().to_vec(),
    )
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
    let (cert, key, expected_public_key) = certificate();
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
        assert_eq!(public_key, expected_public_key);
        assert!(!acceptor.config().key_log.will_log("CLIENT_RANDOM"));
        assert_eq!(identity(&args).unwrap().1, expected_public_key);
        assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
        assert!(fs::read(args.key.unwrap()).unwrap() == key.as_bytes());
    }
}

#[test]
fn pem_identity_ignores_sslkeylogfile() {
    const CHILD: &str = "RDP2VNC_PEM_IDENTITY_KEYLOG_TEST_CHILD";
    const MARKER: &str = "identity keylog assertions completed";
    if std::env::var_os(CHILD).is_none() {
        // Set the environment on a child, never mutate the multithreaded test
        // process environment. The child runs only this test with a writable log.
        let dir = tempfile::tempdir().unwrap();
        let keylog = dir.path().join("session-keys.log");
        fs::write(&keylog, b"unchanged canary\n").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tls::pem_tests::pem_identity_ignores_sslkeylogfile",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env("SSLKEYLOGFILE", &keylog)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "keylog child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains(MARKER));
        assert_eq!(fs::read(keylog).unwrap(), b"unchanged canary\n");
        return;
    }

    let keylog = PathBuf::from(std::env::var_os("SSLKEYLOGFILE").unwrap());
    assert_eq!(fs::read(&keylog).unwrap(), b"unchanged canary\n");
    let (cert, key, _) = certificate();
    for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
        let dir = tempfile::tempdir().unwrap();
        let args = args(
            dir.path(),
            cert_name,
            key_name,
            cert.as_bytes(),
            key.as_bytes(),
        );
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
            // Even a direct callback must not append disposable dummy secrets.
            acceptor.config().key_log.log(label, &[0; 32], &[0; 48]);
        }
    }
    assert_eq!(fs::read(keylog).unwrap(), b"unchanged canary\n");
    eprintln!("{MARKER}");
}

#[test]
fn pem_identity_rejects_empty_damaged_certificates_without_rotation() {
    let (_, key, _) = certificate();
    for cert in [
        "",
        " \r\n\t",
        "damaged certificate",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    ] {
        for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
            let dir = tempfile::tempdir().unwrap();
            let args = args(
                dir.path(),
                cert_name,
                key_name,
                cert.as_bytes(),
                key.as_bytes(),
            );
            assert!(identity(&args).is_err());
            assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
            assert!(fs::read(args.key.unwrap()).unwrap() == key.as_bytes());
        }
    }
}

#[test]
fn pem_identity_rejects_empty_damaged_or_mismatched_keys_without_rotation() {
    let (cert, _, _) = certificate();
    let (_, different_key, _) = certificate();
    // These intentionally invalid PEM bodies are not private keys: "!!!!" is
    // invalid Base64, and "AQID" decodes to three bytes, not a PKCS#8 structure.
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
        for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
            let dir = tempfile::tempdir().unwrap();
            let args = args(
                dir.path(),
                cert_name,
                key_name,
                cert.as_bytes(),
                key.as_bytes(),
            );
            assert!(identity(&args).is_err());
            assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
            assert!(fs::read(args.key.unwrap()).unwrap() == key.as_bytes());
        }
    }
}

#[test]
fn legacy_identity_loader_only_accepts_pkcs8_key_sections() {
    use ironrdp_server::ServerErrorKind;

    let (cert, key) = generated_certificate();
    for key_name in ["server.key", "server.PEM", "server"] {
        for label in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
            // Valid Base64 wrapping deliberately invalid DER distinguishes a
            // rejected PEM label from later cryptographic key validation.
            let unsupported = format!("-----BEGIN {label}-----\nAQID\n-----END {label}-----\n");
            for (keys, has_pkcs8) in [
                (unsupported.clone(), false),
                (format!("{unsupported}{}", key.serialize_pem()), true),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let args = args(
                    dir.path(),
                    "server.crt",
                    key_name,
                    cert.pem().as_bytes(),
                    keys.as_bytes(),
                );
                let loaded = TlsIdentityCtx::init_from_paths(
                    args.cert.as_ref().unwrap(),
                    args.key.as_ref().unwrap(),
                );
                if has_pkcs8 {
                    let loaded = loaded.unwrap();
                    assert!(loaded.priv_key.secret_der() == key.serialize_der());
                    assert_eq!(loaded.pub_key, key.public_key_raw());
                } else {
                    let error = loaded
                        .err()
                        .expect("legacy loader must reject non-PKCS8 labels");
                    assert!(matches!(
                        error.kind(),
                        ServerErrorKind::Reason(reason) if reason == "no private key"
                    ));
                }
                assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.pem().as_bytes());
                assert!(fs::read(args.key.unwrap()).unwrap() == keys.as_bytes());
            }
        }
    }
}

#[test]
fn pem_identity_uses_first_pkcs8_key_without_searching_for_a_match() {
    let (cert, matching_key) = generated_certificate();
    let (_, other_key) = generated_certificate();
    for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
        for (first, second, matches_cert) in [
            (&matching_key, &other_key, true),
            (&other_key, &matching_key, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let keys = format!("{}{}", first.serialize_pem(), second.serialize_pem());
            let args = args(
                dir.path(),
                cert_name,
                key_name,
                cert.pem().as_bytes(),
                keys.as_bytes(),
            );
            let loaded = TlsIdentityCtx::init_from_paths(
                args.cert.as_ref().unwrap(),
                args.key.as_ref().unwrap(),
            )
            .unwrap();
            // Boolean comparisons do not print private key bytes on failure.
            assert!(loaded.priv_key.secret_der() == first.serialize_der());
            assert_eq!(loaded.pub_key, matching_key.public_key_raw());
            if matches_cert {
                assert_eq!(identity(&args).unwrap().1, matching_key.public_key_raw());
            } else {
                let error = identity(&args)
                    .err()
                    .expect("first key must match certificate");
                assert_eq!(error.to_string(), "invalid RDP certificate/key pair");
            }
            assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.pem().as_bytes());
            assert!(fs::read(args.key.unwrap()).unwrap() == keys.as_bytes());
        }
    }
}

#[test]
fn pem_identity_only_parses_key_sections_up_to_the_first_pkcs8_key() {
    let (cert, key, expected_public_key) = certificate();
    for malformed in [
        "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
        "-----BEGIN PRIVATE KEY-----\nAQID\n",
        "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
    ] {
        for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
            for (keys, valid_first) in [
                (format!("{key}{malformed}"), true),
                (format!("{malformed}{key}"), false),
            ] {
                let dir = tempfile::tempdir().unwrap();
                let args = args(
                    dir.path(),
                    cert_name,
                    key_name,
                    cert.as_bytes(),
                    keys.as_bytes(),
                );
                if valid_first {
                    // The existing loader consumes only the first key. A bad
                    // later section must not change the chosen identity.
                    assert_eq!(identity(&args).unwrap().1, expected_public_key);
                } else {
                    // Neither a parse failure nor invalid DER in the first key
                    // permits scanning ahead for a usable matching key.
                    assert!(identity(&args).is_err());
                }
                assert_eq!(fs::read(args.cert.unwrap()).unwrap(), cert.as_bytes());
                assert!(fs::read(args.key.unwrap()).unwrap() == keys.as_bytes());
            }
        }
    }
}

#[test]
fn pem_identity_preserves_certificate_order_and_binds_nla_to_the_first_certificate() {
    let (cert, key) = generated_certificate();
    let (other_cert, other_key) = generated_certificate();
    for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
        for (first, second, expected_public_key, matches_key) in [
            (&cert, &other_cert, key.public_key_raw(), true),
            (&other_cert, &cert, other_key.public_key_raw(), false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let bundle = format!("{}{}", first.pem(), second.pem());
            let args = args(
                dir.path(),
                cert_name,
                key_name,
                bundle.as_bytes(),
                key.serialize_pem().as_bytes(),
            );
            let loaded = TlsIdentityCtx::init_from_paths(
                args.cert.as_ref().unwrap(),
                args.key.as_ref().unwrap(),
            )
            .unwrap();
            assert_eq!(loaded.certs, [first.der().clone(), second.der().clone()]);
            // NLA uses the subjectPublicKey BIT STRING bytes from the first
            // certificate, not its SPKI wrapper or a later matching certificate.
            assert_eq!(loaded.pub_key, expected_public_key);
            if matches_key {
                assert_eq!(identity(&args).unwrap().1, expected_public_key);
            } else {
                let error = identity(&args)
                    .err()
                    .expect("first certificate must match key");
                assert_eq!(error.to_string(), "invalid RDP certificate/key pair");
            }
            assert_eq!(fs::read(args.cert.unwrap()).unwrap(), bundle.as_bytes());
            assert!(fs::read(args.key.unwrap()).unwrap() == key.serialize_pem().as_bytes());
        }
    }
}

#[test]
fn pem_identity_rejects_malformed_trailing_certificate_sections() {
    let (cert, key, _) = certificate();
    for malformed in [
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n",
    ] {
        for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
            let dir = tempfile::tempdir().unwrap();
            let bundle = format!("{cert}{malformed}");
            let args = args(
                dir.path(),
                cert_name,
                key_name,
                bundle.as_bytes(),
                key.as_bytes(),
            );
            // Certificates are collected as a chain, so parsing cannot stop
            // after the first valid entry as it does for the private key.
            assert!(identity(&args).is_err());
            assert_eq!(fs::read(args.cert.unwrap()).unwrap(), bundle.as_bytes());
            assert!(fs::read(args.key.unwrap()).unwrap() == key.as_bytes());
        }
    }
}

#[cfg(unix)]
#[test]
fn pem_identity_rejects_exposed_private_keys_without_modification() {
    use std::os::unix::fs::PermissionsExt;

    let (cert, key, expected_public_key) = certificate();
    for (cert_name, key_name) in [("server.pem", "key.pem"), ("server.crt", "server.key")] {
        let dir = tempfile::tempdir().unwrap();
        let args = args(
            dir.path(),
            cert_name,
            key_name,
            cert.as_bytes(),
            key.as_bytes(),
        );
        let cert_path = args.cert.as_ref().unwrap();
        let key_path = args.key.as_ref().unwrap();
        for mode in [0o640, 0o604, 0o644] {
            fs::set_permissions(key_path, fs::Permissions::from_mode(mode)).unwrap();
            let error = identity(&args)
                .err()
                .expect("group/world-readable private keys must be rejected");
            assert_eq!(
                error.to_string(),
                "TLS private key must not be group/world accessible; chmod 600 it"
            );
            assert_eq!(fs::read(cert_path).unwrap(), cert.as_bytes());
            assert!(fs::read(key_path).unwrap() == key.as_bytes());
            assert_eq!(
                fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
        // Prove rejection was the permission gate, not a broken identity.
        // Owner-read-only keys remain compatible; loading must not chmod them.
        for mode in [0o600, 0o400] {
            fs::set_permissions(key_path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(identity(&args).unwrap().1, expected_public_key);
            assert_eq!(fs::read(cert_path).unwrap(), cert.as_bytes());
            assert!(fs::read(key_path).unwrap() == key.as_bytes());
            assert_eq!(
                fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }
}
