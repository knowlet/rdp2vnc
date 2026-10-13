# Local framebuffer and resource measurements

## Scope and baseline

Measured in an isolated Debian 13 x86-64 cloud workspace (AMD EPYC 7763,
5 visible vCPUs), Rust 1.99.0, on 2026-10-13. All network fixtures bind loopback.
Baseline: PR #1 head `6e33da5cb475d075653b80e33b7481928f0c32ee`.
PR #1 remains unmerged; its 10 review threads were resolved and exact-head
[CI 37787797101](https://github.com/knowlet/rdp2vnc/actions/runs/37787797101)
passed on Linux, Windows and macOS, including Linux FreeRDP integration.
No AGENTS.md or .agents/skills exists in that revision.

This follow-up is based on `feat/rust-rdp-vnc-bridge`, so its PR must target
that branch until PR #1 is merged. Retarget after merging/rebasing the dependency;
do not duplicate the implementation diff against develop.

## Evidence and change

The RFB reader already publishes an immutable full-frame snapshot. The RDP
adapter additionally copied that snapshot into a new Bytes allocation for every
bitmap. A single-threaded opt-in benchmark passes the result through black_box
and drops each update, comparing the original copy implementation against the
current adapter in the same binary. Each size uses 200 handoffs of a populated
snapshot. Setup/filling, RFB decoding, RDP encoding and network I/O are excluded.
Timings are observations, not test thresholds or end-to-end FPS claims.

Initial debug-build baseline before the production change:

| Frame | Copy time / 200 updates | Extra pixel buffer per update |
| --- | ---: | ---: |
| 1920 x 1080 | 67.198 ms | 8,294,400 bytes |
| 3840 x 2160 | 352.866 ms | 33,177,600 bytes |
| 5120 x 2880 | 4197.303 ms | 58,982,400 bytes |
| 8192 x 2048 | 4785.712 ms | 67,108,864 bytes |

The adapter now uses Bytes::from_owner with an Arc-backed view of the published
snapshot. This removes the additional pixel allocation/copy, up to 64 MiB per
handoff. It still allocates small ownership metadata; it is not allocation-free.
The authoritative mutable framebuffer and its publication clone are unchanged.
The encoder can retain a snapshot via Bytes clones/slices until their final drop.

Reproduce the optimized-build comparison:

```sh
cargo test --release --locked --lib measure_bitmap_handoff -- --ignored --nocapture
```

Same-binary release result (single run, 200 iterations per row):

| Frame | Original copy | Shared owner |
| --- | ---: | ---: |
| 1920 x 1080 | 67.683 ms | 0.013 ms |
| 3840 x 2160 | 332.423 ms | 0.005 ms |
| 5120 x 2880 | 4327.677 ms | 0.006 ms |
| 8192 x 2048 | 4908.024 ms | 0.005 ms |

The shared-owner timings are very small and subject to timer/scheduler noise;
the structural result is no pixel copy, verified by pointer identity and owner
lifetime assertions. These numbers are not whole-gateway speedup ratios.

## Resource and correctness coverage

- Pointer identity and clone/slice lifetime test: bitmap data shares the snapshot;
  the owner stays alive through its last slice and is released afterward.
- 1,000 session-state cycles: full reconnect snapshots stay immutable after
  replacement, old snapshot owners are freed, reset precedes admission release,
  and channel/Arc counts return to their baseline. These are component cycles,
  not 1,000 authenticated network connections.
- 1,000,000 pointer events interspersed with 2,000 key edges: each motion run is
  coalesced to its last coordinates, edges stay ordered, and the queue returns
  to full capacity. A 257-event critical burst verifies the existing 256-event
  bound and fail-closed notification.
- Linux loopback socket stress: 100 batches of eight idle handshakes; an extra
  peer is rejected each batch; descriptors return to baseline after each batch.
  A final idle connection must close at its authentication deadline and reclaim
  its descriptor. Observed descriptors: baseline 11, peak 19, final 11.
  No admission/input production logic needed changes.
- Existing independent RFB + real FreeRDP/Xvfb integration checks authenticated
  pixels, keyboard/mouse, losing-peer isolation, reconnects and backend EOF.

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --locked
xvfb-run -a -s '-screen 0 1024x768x24' /usr/bin/python3 tests/e2e_freerdp.py
/usr/bin/python3 tests/stress_connections.py
```

The socket stress test uses /proc and runs only on Linux. Its descriptor checks
cover live socket reclamation, not an exhaustive heap-leak audit or authenticated
session soak. The benchmark is opt-in; deterministic ownership/input tests run
on all CI platforms, with socket stress and FreeRDP integration on Linux.

## Dependency review

`cargo update --dry-run` on 2026-10-13 proposed 14 Rust-1.94-compatible registry
updates: aws-lc-rs 1.18.1→1.18.2, aws-lc-sys 0.45.0→0.46.0, cc 1.6.0→1.8.0,
indoc 2.0.7→2.0.8, libz-sys 1.1.29→1.1.30, serde_json 1.0.151→1.0.154,
sha2 0.11.0→0.11.1, smallvec 1.16.2→1.16.3, syn 3.0.6→3.0.9,
tokio-util 0.7.19→0.7.20, unicode-ident 1.0.26→1.0.27, uuid 1.27.0→1.28.0,
zerocopy/zerocopy-derive 0.8.61→0.8.62. Resolution alone does not prove runtime
compatibility. Existing bytes already provides from_owner; no dependency update
is needed for the measured improvement.

Reviewed the [tokio-util 0.7.20 changelog](https://github.com/tokio-rs/tokio/blob/tokio-util-0.7.20/tokio-util/CHANGELOG.md)
for related buffering/lifecycle fixes. The changed APIs do not establish a fix
for the tested gateway paths. No candidate has a demonstrated benefit for this
patch, so Cargo.lock and the immutable IronRDP pin remain unchanged. This is an
update-availability/targeted relevance check, not a dependency security audit;
no compatibility claim is made for unadopted versions.

## Limits

Full-frame publication cloning and RDP encoding remain potential costs; no
claim is made about network bandwidth, end-to-end latency, heap RSS reduction,
or dirty-region scheduling. The maximum framebuffer limit is unchanged.
Physical Windows mstsc / macOS Screen Sharing interoperability was **not tested**.
No merge, deployment, release, secrets/permissions change, paid service, real
external-host stress or access to a user's computer is part of this work.
