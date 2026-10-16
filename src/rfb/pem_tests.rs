//! Exercise the production VeNCrypt path, not a substitute certificate verifier.
use super::*;
use std::path::Path;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;

fn certificate() -> (rcgen::Certificate, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert, key)
}

async fn connect(
    ca: Option<&Path>,
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    host: &str,
    version: &'static rustls::SupportedProtocolVersion,
) -> (Result<()>, Result<rustls::ProtocolVersion>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let (client, mut server) = tokio::io::duplex(65536);
    let options = Options {
        auth: Auth::None,
        username: None,
        password: Zeroizing::new(String::new()),
        allow_insecure: false,
        ca: ca.map(Path::to_path_buf),
    };
    let client = async {
        let (mut stream, auth) = vencrypt(Box::new(client), host, &options).await?;
        ensure!(auth == 1, "unexpected post-TLS authentication");
        ensure!(
            stream.read_u8().await? == 0x55,
            "missing authenticated payload"
        );
        stream.write_u8(0xaa).await?;
        stream.flush().await?;
        Ok(())
    };
    let server = async move {
        server.write_all(&[0, 2]).await?;
        server.flush().await?;
        let mut version = [0; 2];
        server.read_exact(&mut version).await?;
        ensure!(version == [0, 2], "unexpected VeNCrypt version");
        server.write_all(&[0, 1]).await?;
        server.write_u32(260).await?;
        server.flush().await?;
        ensure!(
            server.read_u32().await? == 260,
            "unexpected VeNCrypt subtype"
        );
        server.write_u8(1).await?;
        server.flush().await?;
        let mut stream = acceptor.accept(server).await?;
        let version = stream
            .get_ref()
            .1
            .protocol_version()
            .context("TLS version absent")?;
        stream.write_u8(0x55).await?;
        stream.flush().await?;
        ensure!(
            stream.read_u8().await? == 0xaa,
            "missing client confirmation"
        );
        Ok(version)
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client, server)
    })
    .await
    .expect("VeNCrypt fixture timed out")
}

#[tokio::test]
async fn pem_ca_trust_succeeds_for_tls12_and_tls13() {
    let (cert, key) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("trusted.crt");
    std::fs::write(&ca, cert.pem()).unwrap();
    for (version, expected) in [
        (&rustls::version::TLS12, rustls::ProtocolVersion::TLSv1_2),
        (&rustls::version::TLS13, rustls::ProtocolVersion::TLSv1_3),
    ] {
        let (client, server) = connect(Some(&ca), &cert, &key, "localhost", version).await;
        client.unwrap();
        assert_eq!(server.unwrap(), expected);
    }
}

#[tokio::test]
async fn pem_ca_bundle_accepts_multiple_certs_crlf_and_unrelated_sections() {
    let (cert, key) = certificate();
    let (other, _) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("bundle.pem");
    // Generated keys are disposable, in-memory fixtures, never repository data.
    let bundle = format!(
        "\n# roots\n{}{}{}\n",
        other.pem(),
        key.serialize_pem(),
        cert.pem()
    );
    std::fs::write(&ca, bundle.replace("\r\n", "\n").replace('\n', "\r\n")).unwrap();
    let (client, server) =
        connect(Some(&ca), &cert, &key, "localhost", &rustls::version::TLS13).await;
    client.unwrap();
    server.unwrap();
}

#[tokio::test]
async fn pem_ca_empty_whitespace_and_key_only_keep_empty_chain_error() {
    let (cert, key) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("empty.pem");
    for text in [String::new(), " \t\r\n\n".into(), key.serialize_pem()] {
        std::fs::write(&ca, text).unwrap();
        let (client, _) =
            connect(Some(&ca), &cert, &key, "localhost", &rustls::version::TLS13).await;
        assert_eq!(
            client.unwrap_err().to_string(),
            "VNC CA file contains no certificates"
        );
    }
}

#[tokio::test]
async fn pem_ca_malformed_and_truncated_input_remain_invalid_data() {
    let (cert, key) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("broken.pem");
    for text in [
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAQID\n",
    ] {
        for prefix in [String::new(), cert.pem()] {
            std::fs::write(&ca, format!("{prefix}{text}")).unwrap();
            let (client, _) =
                connect(Some(&ca), &cert, &key, "localhost", &rustls::version::TLS13).await;
            let error = client.unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }
}

#[tokio::test]
async fn pem_ca_invalid_der_is_not_silently_ignored() {
    let (cert, key) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("invalid-der.pem");
    std::fs::write(
        &ca,
        format!(
            "{}-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            cert.pem()
        ),
    )
    .unwrap();
    let (client, _) = connect(Some(&ca), &cert, &key, "localhost", &rustls::version::TLS13).await;
    assert!(matches!(
        client.unwrap_err().downcast_ref::<rustls::Error>(),
        Some(rustls::Error::InvalidCertificate(_))
    ));
}

#[tokio::test]
async fn pem_ca_missing_file_preserves_open_context_and_io_error() {
    let (cert, key) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let (client, _) = connect(
        Some(&dir.path().join("missing.pem")),
        &cert,
        &key,
        "localhost",
        &rustls::version::TLS13,
    )
    .await;
    let error = client.unwrap_err();
    assert_eq!(error.to_string(), "opening VNC CA certificate");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[tokio::test]
async fn pem_ca_untrusted_certificate_has_no_insecure_fallback() {
    let (cert, key) = certificate();
    let (other, _) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("unrelated.pem");
    std::fs::write(&ca, other.pem()).unwrap();
    for ca in [None, Some(ca.as_path())] {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let (client, _) = connect(ca, &cert, &key, "localhost", version).await;
            let error = client.unwrap_err();
            assert_eq!(
                error.to_string(),
                "VNC TLS validation failed (no insecure certificate fallback)"
            );
            let tls_error = error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .get_ref()
                .unwrap()
                .downcast_ref::<rustls::Error>()
                .unwrap();
            // Both generated certificates have the same issuer name but different keys.
            // Preserve the baseline distinction: no anchor versus a wrong-key anchor.
            if ca.is_some() {
                assert!(
                    matches!(
                        tls_error,
                        rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
                    ),
                    "{tls_error:?}"
                );
            } else {
                assert!(
                    matches!(
                        tls_error,
                        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
                    ),
                    "{tls_error:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn pem_ca_trusted_certificate_still_requires_matching_hostname() {
    let (cert, key) = certificate();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("trusted.pem");
    std::fs::write(&ca, cert.pem()).unwrap();
    let (client, _) = connect(
        Some(&ca),
        &cert,
        &key,
        "wrong.invalid",
        &rustls::version::TLS13,
    )
    .await;
    let error = client.unwrap_err();
    let tls_error = error
        .downcast_ref::<std::io::Error>()
        .unwrap()
        .get_ref()
        .unwrap()
        .downcast_ref::<rustls::Error>()
        .unwrap();
    assert!(matches!(tls_error, rustls::Error::InvalidCertificate(_)));
    assert!(
        format!("{tls_error:?}").contains("NotValidForName"),
        "{tls_error:?}"
    );
}
