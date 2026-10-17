# IronRDP PEM maintenance candidate

These patches support [rdp2vnc #13](https://github.com/knowlet/rdp2vnc/issues/13).
They are reviewable source changes, not a published IronRDP revision. The
application's committed `Cargo.toml` and `Cargo.lock` on this validation branch
still use the original upstream revision. Do not merge this validation branch
as the final dependency adoption or close #13 from its CI result alone.

## Source provenance

| Patch | Exact base commit | Scope |
| --- | --- | --- |
| `ironrdp-pemobject-upstream.patch` | `62246b364a0282bab85087f658a81fe4207b6b31` | Upstream helper/feature migration, regression tests and Cargo-generated workspace lockfile |
| `ironrdp-pemobject-backport.patch` | `8e76c3168da578826d8fd707503655ea16bd3392` | The same production change and tests on rdp2vnc's actual pinned revision |
| `../../tests/fixtures/ironrdp-pemobject.patch` | `8e76c3168da578826d8fd707503655ea16bd3392` | Only the two production files, applied by the candidate CI workflow |

The inspected upstream helper and server manifest have identical contents at
both base commits. No already-merged replacement was found in that inspected
upstream snapshot. The server package's `0.13.0` version is not sufficient to
identify its source: the application's Git commit is the backport base.

Apply each full patch in a clean checkout at its stated base using
`git apply --check PATH` followed by `git apply PATH`. Both full patches include
the `server_helper` tests in the central `ironrdp-testsuite-extra` harness; the
server crate's own unit-test harness remains disabled as upstream intends.

## Preserved behavior

The legacy certificate branch now uses `CertificateDer::pem_reader_iter`.
The legacy private-key branch uses `PrivatePkcs8KeyDer::pem_reader_iter` and
selects only its first result. PKCS#1, SEC1 and encrypted-key sections do not
become accepted legacy identities. A malformed or mismatched first PKCS#8 key
does not cause a search for a later matching key. A malformed section after
the selected first key retains the prior unread-tail behavior.

The generic `.pem` paths are unchanged. The files still require PEM data;
the old helper comment did not reflect binary-DER support. X.509 strict DER
parsing, aligned raw subjectPublicKey extraction for NLA, and rustls
certificate/key matching remain intact. Underlying I/O error kinds remain
I/O errors, and malformed legacy PEM retains `InvalidData` classification.
Only the optional `rustls-pemfile` dependency and its helper feature edge are
removed. The application continues to build its own acceptor with key logging
disabled.

The added upstream tests cover legacy and generic extensions, ordered bundles,
CRLF, ignored sections, first-key selection, malformed input, missing files,
invalid X.509 and BIT STRING alignment, key mismatch, and verified TLS 1.2/1.3
handshakes. Key-format category tests using deliberately invalid DER do not
claim a successful handshake with valid PKCS#1 or SEC1 private keys.

## Reproduce candidate application validation

The `PEM backport candidate validation` workflow runs Linux, macOS and Windows
on stable Rust and Rust 1.94.0. It checks out the exact original IronRDP commit,
then runs `tests/prepare_pem_backport.py` to apply the production patch and
temporarily substitute a local path dependency. Cargo, rather than a textual
lockfile edit, produces the candidate application lockfile.

The preparation script requires every remaining registry package entry,
version, checksum and dependency list to match the original lockfile. It also
checks the whole normalized lockfile and verifies that all 23 IronRDP packages
come from the same patched checkout. Its only allowed dependency change is
removing `rustls-pemfile` and the server's edge to it.

After preparation, test, Clippy, build and graph checks all use `--locked`.
The graph check inspects all lockfile entries, resolves metadata for all
platforms, and requires Cargo's specific absent-package diagnostic. A failed
Cargo resolution is not treated as successful removal. Linux stable also runs
both `.pem` and `.crt/.key` FreeRDP NLA loopback modes and the existing socket
resource stress test. `cargo fmt` uses its supported `--all -- --check` form.

The generated local-path manifest and lockfile are validation artifacts and
must not be committed as the shipping dependency configuration.

## Current audit comparison

`cargo-audit 0.22.2` was run without ignored advisories on both the original
application lockfile and the Cargo-generated candidate lockfile. The saved
reports are `audit-before.json` and `audit-candidate.json`. Both use RustSec
database commit `64f92cdc64401fab47baa10e2e11fe382aa57155` (1,334 advisories,
last update `2026-10-17T01:27:42+02:00`).

The complete application graph changes from 447 to 446 packages. The only
removed audit finding is `rustls-pemfile 2.2.0` / RUSTSEC-2025-0134. No new
audit finding appears in the candidate. Both audit commands exit **1** because
the following unrelated findings remain; the candidate is not a clean audit.

| Classification | Package | Advisory IDs |
| --- | --- | --- |
| Vulnerability | `rsa 0.10.0-rc.18` | RUSTSEC-2023-0071 |
| Vulnerability | `rustls 0.23.45` | RUSTSEC-2026-0346, RUSTSEC-2026-0347, RUSTSEC-2026-0348, RUSTSEC-2026-0349 |
| Unmaintained | `atomic-polyfill 1.0.3` | RUSTSEC-2023-0089 |
| Unmaintained | `paste 1.0.15` | RUSTSEC-2024-0436 |
| Unsound | `lru 0.12.5` | RUSTSEC-2026-0002, RUSTSEC-2026-0253 |

These are five vulnerability records and four other warning records. They
require separate triage and do not establish exploitability in rdp2vnc merely
by appearing in its dependency tree. The narrow PEM change does not update
unrelated cryptographic packages or suppress scanner output. A final remote
SHA adoption still requires a fresh audit of its committed lockfile.

## Integration gate

Publish the upstream patch in an IronRDP fork and open the upstream PR first.
If adopting before upstream acceptance, publish the narrowly scoped backport,
pin its full remote commit SHA in rdp2vnc, regenerate Cargo.lock, and repeat the
locked tests and CI on that final source configuration. Preserve this
provenance so that the backport can later be replaced by a reviewed upstream
revision.

Run a current `cargo audit` for the final candidate and record unrelated
findings separately. Removal of the INFO / Unmaintained advisory
RUSTSEC-2025-0134 does not establish a fully clean vulnerability audit.
Physical mstsc/macOS Screen Sharing acceptance remains in #10; passing Unix
permission tests does not establish Windows ACL hardening.
