# Dependency maintenance review — 2026-10-13

## Scope and merge dependency

Update the 14 registry packages identified from implementation PR #1 head
`6e33da5cb475d075653b80e33b7481928f0c32ee`. This branch is based directly on
`feat/rust-rdp-vnc-bridge`, independently of performance PR #2. Both follow-ups
require PR #1's implementation, but neither requires the other. Target PR #1's
branch until it is merged, then retarget/rebase onto develop. Do not duplicate
the implementation diff. No merge is performed here.

The application manifest and its Rust 1.94 requirement are unchanged. IronRDP
stays pinned to `8e76c3168da578826d8fd707503655ea16bd3392`. Exactly 14 registry
package versions change; no additional packages are added or removed. Existing
unrelated getrandom/windows-sys selections on broad dependency ranges were
preserved rather than taking incidental resolver changes.

## Per-package review and adoption

All rows below are adopted. Sources are upstream release notes, tagged manifests
and published crate sources; intermediary releases were checked where present.
MSRV columns refer to the package's declared rust-version, not an inferred floor.
A missing declaration is reported explicitly and covered by the actual project
Rust 1.94 build/test. All selected releases are stable and fit the existing
parent requirements, including the deliberate aws-lc-rs/aws-lc-sys pairing.

| Package | Version update | Declared MSRV old → new | Reviewed change and primary source |
| --- | --- | --- | --- |
| aws-lc-rs | 1.18.1 → 1.18.2 | 1.71 → 1.71 | Pairs with sys 0.46; RSA/EdDSA parameter equality, WASI support and nonce documentation. [Release](https://github.com/aws/aws-lc-rs/releases/tag/v1.18.2). |
| aws-lc-sys | 0.45.0 → 0.46.0 | 1.71 → 1.71 | Bundled AWS-LC 5.7 → 5.11, native build and cryptographic implementation fixes. [Wrapper/sys release](https://github.com/aws/aws-lc-rs/releases/tag/v1.18.2), [AWS-LC releases](https://github.com/aws/aws-lc/releases). |
| cc | 1.6.0 → 1.8.0 | 1.65 → 1.65 | [1.7](https://github.com/rust-lang/cc-rs/releases/tag/cc-v1.7.0): compiler/environment detection, caching, assembly selection; [1.8](https://github.com/rust-lang/cc-rs/releases/tag/cc-v1.8.0): panic/jobserver fixes, polling scheduler, corrected target crt-static and PGO flag handling. |
| indoc | 2.0.7 → 2.0.8 | **1.60 → 1.71** | Adds panicdoc!; compiler support policy advances. [Release](https://github.com/dtolnay/indoc/releases/tag/2.0.8). |
| libz-sys | 1.1.29 → 1.1.30 | Not declared → not declared | Native build target fixes for AArch64 CRC and wasm Z_SOLO; vendored zlib source unchanged. [Release](https://github.com/rust-lang/libz-sys/releases/tag/1.1.30), [source comparison](https://github.com/rust-lang/libz-sys/compare/1.1.29...1.1.30). |
| serde_json | 1.0.151 → 1.0.154 | 1.71 → 1.71 | [.152](https://github.com/serde-rs/json/releases/tag/v1.0.152): arbitrary-precision negative zero and f32 infinity equality; [.153](https://github.com/serde-rs/json/releases/tag/v1.0.153): invalid UTF-8 error location; [.154](https://github.com/serde-rs/json/releases/tag/v1.0.154): no_std preserve_order support. |
| sha2 | 0.11.0 → 0.11.1 | **1.85 → 1.88** | AArch64 Stacked Borrows correction and RISC-V backend features/refactoring. [Tagged changelog](https://github.com/RustCrypto/hashes/blob/sha2-v0.11.1/sha2/CHANGELOG.md). Direct application sha2 0.10.9 remains separate. |
| smallvec | 1.16.2 → 1.16.3 | Not declared → not declared | Undersized grow/try_grow requests become no-ops rather than panicking; fuzz coverage. [Release](https://github.com/servo/rust-smallvec/releases/tag/v1.16.3), [fix](https://github.com/servo/rust-smallvec/pull/693). |
| syn | 3.0.6 → 3.0.9 | 1.71 → 1.71 | [.7](https://github.com/dtolnay/syn/releases/tag/3.0.7): labeled-break absolute-path parsing; [.8](https://github.com/dtolnay/syn/releases/tag/3.0.8): arrow-token parsing; [.9](https://github.com/dtolnay/syn/releases/tag/3.0.9): additive Punctuated::retain. |
| tokio-util | 0.7.19 → 0.7.20 | **1.71 → 1.85** | Buffer reserve optimization; frame length, interrupted/vectored I/O, EOF, cancellation locking and DelayQueue fixes. [Changelog](https://github.com/tokio-rs/tokio/blob/tokio-util-0.7.20/tokio-util/CHANGELOG.md). |
| unicode-ident | 1.0.26 → 1.0.27 | 1.71 → 1.71 | Trie layout optimization for future Unicode headroom; Unicode 18 identifier classification unchanged. [Release](https://github.com/dtolnay/unicode-ident/releases/tag/1.0.27). |
| uuid | 1.27.0 → 1.28.0 | 1.89 → 1.89 | Additive Option<Uuid> serde adapters for six formats. [Release](https://github.com/uuid-rs/uuid/releases/tag/v1.28.0). |
| zerocopy | 0.8.61 → 0.8.62 | 1.56 → 1.56 | Keeps explicit DST trailing-element counts in Ref; proof/Miri/codegen maintenance. [Release](https://github.com/google/zerocopy/releases/tag/v0.8.62). |
| zerocopy-derive | 0.8.61 → 0.8.62 | Not declared → not declared | Paired refresh required by zerocopy's exact version pin; published Rust source/dependency requirements unchanged. [Paired release](https://github.com/google/zerocopy/releases/tag/v0.8.62). |

## Compatibility and security boundaries

Three package MSRVs advance, all below the application's existing Rust 1.94.
A Linux CI job now compiles and tests with Rust 1.94.0 so future lock updates
cannot silently exceed the project minimum. No application API migration,
project MSRV increase, or IronRDP revision change is required by these updates.
Tokio-util now requires Tokio >=1.51; the existing lock already has Tokio 1.53.2.

The aws-lc-sys 0.x minor update is adopted as the version explicitly required by
aws-lc-rs 1.18.2, rather than treating an arbitrary pre-1.0 minor as interchangeable.
Bundled AWS-LC is exercised by native CI builds; installed-system AWS-LC users
have an upstream minimum change from 1.68 to 5.7 for non-FIPS linking. The default
bundled path does not require such an installation. Native compiler detection,
assembly and scheduler changes warrant Linux, Windows and macOS build coverage.
No custom compiler/PGO/system-library configuration is established by those CI
results.

Bundled AWS-LC changes include rejection of non-canonical Ed25519 inputs in the
no-hardware decoder ([#3457](https://github.com/aws/aws-lc/pull/3457)),
ChaCha20-Poly1305 zeroization ([#3552](https://github.com/aws/aws-lc/pull/3552))
and corrected ML-KEM CPU-feature selection ([#3596](https://github.com/aws/aws-lc/pull/3596)).
These are upstream cryptographic hardening/correctness changes, not proof of an
exploitable gateway vulnerability. AWS-LC libssl/CLI changes are not described as
fixes to the application's rustls TLS state machine; this dependency path does
not enable AWS-LC libssl.

Zerocopy's [upstream correctness advisory](https://github.com/google/zerocopy/issues/3618)
says explicit DST counts could be lost and padding interpreted as extra elements.
It does not establish undefined behavior, an out-of-allocation read or an
application security bypass. Serde_json's new no_std preserve_order path has
limited HashDoS resistance ([upstream explanation](https://github.com/serde-rs/json/pull/1333));
that optional feature is absent from the resolved project graph. The remaining
reviewed release notes do not identify a security remediation. This review of
release changes is not a comprehensive vulnerability audit.

## Validation and reproduction

Local cloud fixture results on Debian 13 x86-64, Rust 1.94.0:

- cargo test --locked --all-targets: **45 passed** (34 library + 11 CLI tests).
- cargo fmt --all -- --check, Clippy with -D warnings, and cargo build --locked:
  passed with Rust 1.94.0; stable formatting also passed.
- Independent RFB fixture with FreeRDP 3.15.0 under Xvfb: passed idle-peer
  admission, NLA rejection, rendered pixels, keyboard/mouse, losing-peer
  isolation, concurrent rejection, reconnect snapshot and backend EOF.
- Additional standalone socket stress from PR #2's fixture, run against this
  branch's binary: 800 idle handshakes reclaimed, 100 excess peers rejected,
  authentication timeout reclaimed; descriptors **11 → 19 → 11**. It is a
  local fixture check, not a source dependency on PR #2.

```sh
cargo +1.94.0 test --locked --all-targets
cargo +1.94.0 clippy --locked --all-targets -- -D warnings
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 build --locked
xvfb-run -a -s '-screen 0 1024x768x24' /usr/bin/python3 tests/e2e_freerdp.py
# Optional: run tests/stress_connections.py from commit 4f060718... as a
# standalone loopback fixture, with this checkout as the working directory.
```

CI performs stable tests/lint/format/build on Linux, Windows and macOS, Linux
FreeRDP integration, and Linux build/test on Rust 1.94. Inspect the final commit's
actual run linked from the PR for completion, rather than inferring success from
the workflow definition. The test count reflects the independent PR #1 base;
PR #2's three added component tests and benchmark are not copied into this diff.

All network checks used this cloud environment and loopback fixtures. Physical
Windows mstsc / macOS Screen Sharing interoperability remains **untested**.
No merge, deployment, release, secrets/permission change, paid service or real
external-host stress is included.
