# PEM parsing maintenance

This document records the bounded resolution of [#11](https://github.com/knowlet/rdp2vnc/issues/11) by [#12](https://github.com/knowlet/rdp2vnc/pull/12). Complete removal of the remaining transitive package is tracked independently in [#13](https://github.com/knowlet/rdp2vnc/issues/13).

## Reproducible #13 candidate, pending integration

This validation branch includes a focused upstream patch and an equivalent
backport to the actual pinned IronRDP revision. See
[patch provenance, validation and audit comparison](patches/README.md).
The committed application manifest and lockfile still describe the original
pin; the candidate workflow applies the production patch to an exact source
checkout and uses a temporary path dependency only while running tests.

Candidate lock validation confirms all 23 IronRDP packages are coherent and
all 422 remaining registry entries are unchanged. The candidate lockfile
contains 446 packages, with no `rustls-pemfile` entry or dependency edge.
The current candidate audit no longer reports RUSTSEC-2025-0134, but retains
five unrelated vulnerability records and four other warnings. It therefore
still exits 1; the saved before/after reports do not claim a fully clean audit.

The candidate CI graph check requires absence from the entire lockfile and
all-platform metadata, then accepts only the specific absent-package result
from the all-target reverse-dependency command. New platform-neutral tests
call the identity loader directly to reject unsupported legacy key labels
and preserve first-PKCS#8 selection. The Linux candidate workflow exercises
both generated `.pem` and explicit `.crt/.key` identities through FreeRDP/NLA.

Before closing #13, publish and review the upstream contribution, publish any
required minimal backport at a full remote commit SHA, update the shipping
dependency and lockfile, and repeat all integration gates on that final
configuration. The original migration and residual-dependency record below
continues to describe the committed baseline until then.

## Scope and source inspection

The integration baseline is `536be2c1f986c3471cbbe294d85c132645368f84`. The application previously called `rustls_pemfile::certs` only in `src/rfb.rs` for the optional VeNCrypt CA bundle. That call now uses `CertificateDer::pem_reader_iter` and the `PemObject` trait through `tokio_rustls::rustls::pki_types`, an existing supported re-export. No new cryptographic dependency is introduced.

RDP identity loading remains delegated to `TlsIdentityCtx::init_from_paths` in [the pinned IronRDP helper](https://github.com/Devolutions/IronRDP/blob/8e76c3168da578826d8fd707503655ea16bd3392/crates/ironrdp-server/src/helper.rs):

| Input path | Existing parser |
| --- | --- |
| Certificate with `.pem` extension | `CertificateDer::pem_file_iter` |
| Private key with `.pem` extension | `PrivateKeyDer::from_pem_file` |
| Certificate with another extension | `rustls_pemfile::certs` |
| Private key with another extension | First PKCS#8 key from `rustls_pemfile::pkcs8_private_keys` |

The `.crt`/`.key` compatibility tests contain PEM data. The helper's documentation mentions DER, but its legacy branch actually parses PEM; this migration does not claim binary DER support or change accepted key formats. The upstream default-branch helper inspected on 2026-10-17 (Taipei) had the same content as the pin.

Replacing the RDP helper locally would duplicate X.509 parsing and NLA subject-public-key extraction without being necessary for the direct migration. Its strict DER decode, byte-aligned subjectPublicKey extraction and the application's `with_single_cert` key-matching validation are retained. The application deliberately does not call `make_acceptor`, which enables environment-controlled session-key logging upstream.

## Remaining advisory: not a fully clean dependency graph

[RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134.html) is an **INFO / Unmaintained** advisory, not a newly demonstrated exploitable vulnerability. Removing the application's dependency edge does not eliminate it:

```text
rustls-pemfile v2.2.0
└── ironrdp-server v0.13.0 (8e76c316)
    └── rdp2vnc v0.1.0
```

IronRDP's `helper` feature enables its optional `rustls-pemfile` dependency. The manifest and lockfile migration remove only the root application's edge; package versions, checksums and the IronRDP revision are unchanged. No broad advisory ignore or scanner suppression is added.

Linux CI parses **every package entry** in Cargo.lock, rejects a reintroduced direct/application or other unexpected consumer, records all-target normal/build/dev reverse dependencies, and checks that inspection does not mutate the lockfile. It explicitly reports the residual advisory rather than calling this migration a full security audit.

Reproduce the inventory with:

```sh
cargo tree --locked --target all --edges normal,build,dev --invert rustls-pemfile
```

When a candidate removes the package, verify the complete lockfile too: absence from a target-specific active graph alone is insufficient. A separate current `cargo audit` report is required before saying the advisory is gone; neither this inventory nor a passing build establishes that all dependencies are vulnerability-free.

## Security and regression boundaries

The production VeNCrypt path preserves its buffered reader, I/O error kinds and diagnostics, strict empty-chain and invalid-DER rejection, existing trust roots and hostname validation. There is no insecure validation fallback. TLS 1.2/1.3, provider selection, NLA, certificate fingerprinting and disabled key logging are unchanged.

The new regressions cover real in-memory VeNCrypt TLS 1.2/1.3 handshakes; multi-certificate/CRLF bundles and unrelated sections; empty, malformed Base64, truncated and malformed-DER input; missing CA files; unknown issuers, wrong-key anchors and wrong hostnames. Identity tests preserve PEM and legacy extensions, compare the NLA public key with an independently generated fixture key, reject malformed/mismatched identities without rotation, and test a writable SSLKEYLOGFILE canary in an isolated child process.

The Unix permission regression rejects group/world-readable `0640`, `0604` and `0644` keys and accepts owner-only `0600` and `0400`, while asserting no content or permission changes. Existing tests retain generated file mode `0600`, directory mode `0700`, create-new/no-overwrite behavior, interrupted-write recovery, legacy identity preservation, and barrier-synchronized concurrent initializers publishing one matching pair.

**Windows limitation:** POSIX mode tests are Unix-only. Windows builds and platform-neutral tests do not prove Windows ACL hardening. Existing per-user directory placement/inherited ACL behavior is unchanged; deployments must separately protect custom private-key paths with appropriate Windows ACLs.

Physical Windows mstsc/macOS Screen Sharing acceptance remains open in [#10](https://github.com/knowlet/rdp2vnc/issues/10). Linux FreeRDP loopback verifies NLA and bridge behavior, but its existing `/cert:ignore` is not evidence of certificate-trust validation. Trust tests use the actual VeNCrypt verifier without bypasses.

## Actionable upstream exit plan

1. Migrate the remaining IronRDP legacy branches to `CertificateDer::pem_reader_iter` and **`PrivatePkcs8KeyDer::pem_reader_iter`**, preserving first-PKCS#8 selection and errors rather than inadvertently accepting additional key formats.
2. Remove `dep:rustls-pemfile` from the server helper feature and its optional dependency after verifying no remaining callers. Preserve the strict X.509/NLA extraction and application's certificate/key matching.
3. Prefer a reviewed upstream commit/release. An urgent zero-advisory requirement can use an auditable minimal backport/fork pinned to a full SHA, with coherent IronRDP workspace dependencies, not an arbitrary unreviewed upgrade or dummy replacement crate.
4. Regenerate/review Cargo.lock; repeat stable and Rust 1.94 Linux/Windows/macOS locked tests/builds, Clippy/fmt, Linux loopback/stress and all identity/trust/permission regressions. Test the upstream legacy paths actually changed.
5. Close #13 only after the package is absent from the **complete** lockfile and resolved graph and a current audit no longer reports this advisory. Record any unrelated audit findings separately and update this document.
