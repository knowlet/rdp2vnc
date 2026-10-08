# Architecture and deliberate boundaries

## Two independent security endpoints

`mstsc -> RDP/TLS/NLA listener -> framebuffer/input adapter -> RFB client -> VNC desktop`.

RDP client credentials authenticate the gateway. VNC/ARD credentials authenticate the backend. A successful VNC login never grants unauthenticated RDP access. TLS-only and legacy RDP are not exposed by the CLI. A 30-second deadline covers RDP connection setup; subsequent sessions can remain open. Extra clients are immediately closed instead of accumulating an application queue.

The backend is connected before the RDP listener is opened. The whole initial VNC/SSH handshake has a 30-second deadline. DNS/TCP setup has an additional 10-second limit. Authentication failures terminate without downgrade retries. An explicit CA file requires X509 VeNCrypt, even on loopback or an SSH connection; it cannot be silently bypassed.

System OpenSSH is launched without a shell, with validated arguments, `BatchMode=yes`, `StrictHostKeyChecking=yes`, keepalives, and `-W`. It must terminate on the VNC host and forward only to loopback, avoiding an unencrypted final network hop. The child is owned by the transport and terminated on drop. New host-key enrollment remains an explicit user task.

Classic DES VNC authentication and ARD's DH/MD5/AES credential exchange are compatibility mechanisms, not modern transport encryption or server authentication. ARD group sizes and public values are bounded/checked, but this is not a new cryptographic protocol or a claim of constant-time BigUint arithmetic. Sensitive buffers use zeroization where supported; upstream credential strings and big integers are not guaranteed to be wiped from every allocation.

## Frame ownership

`rfb.rs` owns the authoritative BGRX framebuffer. Raw/Hextile/ZRLE updates and overlapping CopyRect operations are applied there. A Tokio watch channel retains the latest complete snapshot, not an unbounded backlog of deltas. Slow RDP clients may skip obsolete snapshots without corrupting CopyRect dependencies. Every new RDP client receives a complete snapshot, even if the VNC desktop is static.

The adapter gives complete images to IronRDP's bitmap encoder. It does not inherit the legacy C project's 8192-byte row slicing bug. This is a correctness-first baseline: full-frame cloning/encoding costs CPU/memory on large displays. Dirty-region scheduling and codec tuning require benchmarks and are not advertised as completed optimizations.

DesktopSize updates resize the backend framebuffer and precede corresponding RDP pixels. Client window size is not permission to reconfigure the Mac's physical monitors. No unimplemented encoding is advertised. Unknown payload types fail closed rather than attempting an unsafe guessed skip.

## Limits and cancellation

Frame: at most 8192 per dimension and 16,777,216 pixels. Text: bounded per message, at most 1 MiB clipboard discard. Compressed rectangle: 32 MiB; decompressed ZRLE has a rectangle-derived ceiling and a 128 MiB absolute cap. Rectangle count: 4096, including LastRect streams. Input queue: 256 events. Held keys: 256. A full input queue terminates the bridge rather than silently dropping a key-release.

RFB parsing has a dedicated reader so asynchronous input events cannot cancel a partially read packet and desynchronize the stream. Writes have a 10-second operation timeout. No generic receive-idle timeout is imposed on static desktops. A peer that stalls midway through an update remains a resource-exhaustion consideration; this initial gateway is not intended for hostile public service deployment.

Key releases use the keysym recorded at key-down, even when Shift/lock state changes. Disconnect/Ctrl+C sends a best-effort reset with a deadline before closing the transport. The VNC worker's JoinHandle is consumed only once. Backend EOF is an error, not a stale-display reconnect loop.

## Dependencies and reproducibility

IronRDP is pinned to `8e76c3168da578826d8fd707503655ea16bd3392`. Its published `ironrdp-server 0.13.0` API predates the button-coordinate and post-authentication lifecycle hooks used here, despite the development crate retaining that version number. This explicit Git pin avoids silently building against either an incompatible crates.io API or a moving branch. `Cargo.lock` covers transitive dependencies; builds/tests use `--locked`.

Application code forbids unsafe Rust. This does not imply that every transitive dependency is Rust-only, free of unsafe code, audited, or vulnerability-free. Dependency advisories and native platform tests remain necessary before a production release.
