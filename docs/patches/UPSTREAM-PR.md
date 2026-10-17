# Proposed upstream PR

Title: `fix(server): migrate remaining PEM readers to rustls-pki-types`

## Description

The server's `helper` feature still pulls in the unmaintained
`rustls-pemfile` crate for certificate and key paths whose extension is not
`.pem`. Downstream consumers therefore retain RUSTSEC-2025-0134 after
migrating their own parsers. This advisory records maintenance status; this
change does not claim to fix a demonstrated exploitable vulnerability.

Replace the legacy certificate reader with
`CertificateDer::pem_reader_iter` and the legacy key reader with
`PrivatePkcs8KeyDer::pem_reader_iter`. Keep first-PKCS#8 selection, the
existing unread-tail behavior, and the distinction between I/O failures,
malformed PEM and absent keys. The generic `.pem` branches, strict X.509
parsing, NLA public-key extraction and certificate/key validation are
unchanged. Correct the format documentation to describe the PEM data that
the implementation actually accepts.

Remove the now-unused optional dependency and helper feature edge. The
Cargo-generated workspace lockfile removes `rustls-pemfile` without changing
the versions or checksums of any remaining registry packages. The test suite
uses dependencies already present in the workspace graph.

Add regressions in the central extra test suite for legacy PKCS#8-only
selection, invalid/mismatched first keys, certificate order, malformed input,
X.509 and BIT STRING validation, I/O error kinds, and trusted TLS 1.2/1.3
handshakes with `.crt/.key` identities. Generated private-key bytes are never
included in assertion diagnostics.

## Validation recorded during preparation

On Linux with Rust 1.94.1:

```sh
cargo test --locked --offline -p ironrdp-testsuite-extra --test integration_tests_extra server_helper
cargo fmt --all -- --check
cargo clippy --locked --offline -p ironrdp-server -p ironrdp-testsuite-extra --all-targets --features helper -- -D warnings
```

All 30 helper tests, formatting and the scoped Clippy command passed. The
complete workspace lock comparison confirms the single package removal and
the expected server/test-suite dependency-list changes. The upstream PR's
full CI and maintainer review remain required after submission; this prepared
text does not claim they have run.

Relates-to: https://github.com/knowlet/rdp2vnc/issues/13
