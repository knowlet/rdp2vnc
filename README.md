# rdp2vnc

A small Rust CLI for using **Windows `mstsc` with an existing Linux or macOS VNC desktop**.

```text
mstsc / FreeRDP  -- RDP + TLS + NLA -->  rdp2vnc  -- RFB over SSH / X509 TLS -->  VNC server
```

The program is an **RDP server and VNC client**. It does not start another desktop, run xrdp, capture the bridge machine's screen, or install a service on your Mac. The project name describes the client-to-backend connection direction. It is not `sshtools/rdp2vnc`, which serves the opposite direction.

**First implementation, not a production security gateway.** Automated protocol tests and native CI builds do not establish compatibility with every version of Windows `mstsc` or macOS Screen Sharing. See [the compatibility and test matrix](docs/compatibility.md), including unimplemented features.

## Build

```sh
git clone https://github.com/knowlet/rdp2vnc.git
cd rdp2vnc
# Until the implementation PR is merged:
git switch feat/rust-rdp-vnc-bridge
cargo build --release --locked
```

Use `target/release/rdp2vnc` (`rdp2vnc.exe` on Windows), or install with `cargo install --path . --locked`. Rust 1.94 or newer and a native C/C++ build toolchain/CMake may be required by cryptographic dependencies. The toolchain file selects stable Rust. The RDP dependency is pinned to an immutable IronRDP revision and the complete dependency graph is locked; it does not follow a floating `master` branch.

## No arguments: terminal setup

```sh
rdp2vnc
```

A keyboard-driven form asks for the VNC target, optional SSH destination, optional Mac username, VNC password, RDP listen address, and separate RDP credentials. Passwords are masked and the form is not persisted. A blank RDP password generates a random one and shows it once to the controlling terminal after setup.

Tab / Shift+Tab or arrow keys select a field; F5 or Enter connects; Esc / Ctrl+C cancels. F2 permits a remote RDP bind, F3 explicitly accepts an unencrypted VNC leg, and F4 enables read-only mode. No arguments without a terminal fail with an actionable error rather than hanging on input.

## CLI: recommended Mac connection

Enable macOS Screen Sharing (or the appropriately configured Remote Management service) and Remote Login. Authorize your account. First connect using normal `ssh user@mac.local`, verify/enroll its host key, and configure SSH key or agent authentication.

Run on the **Windows computer beside mstsc**, or another supported bridge host:

```sh
rdp2vnc 127.0.0.1:5900 --ssh user@mac.local --username user
```

Here `127.0.0.1:5900` is the VNC service **on the SSH destination**, not on your Windows computer. The SSH helper uses strict host-key checking and batch/key authentication. It never silently accepts a new/changed SSH host key. The Mac account password is used for Apple ARD authentication; the RDP gateway uses a separate account and password.

Then on Windows:

```powershell
mstsc /v:127.0.0.1:3390
```

Default RDP username: `rdp2vnc`. Use the separately supplied/generated gateway password, not the Mac password. On first use the self-signed RDP certificate is untrusted: verify the printed SHA-256 fingerprint before trusting it. For managed use, provide a trusted certificate with an appropriate hostname/IP SAN using `--cert` and `--key`.

macOS Screen Sharing permissions, login-window behavior, sleep/headless behavior, and allowed authentication methods remain controlled by macOS. The implementation recognizes Apple's `RFB 003.889` banner and implements ARD security type 30; physical macOS/mstsc interoperability is a separate acceptance check, not implied by a successful Rust build.

## Other connections

Local Linux VNC or an already established local tunnel:

```sh
rdp2vnc 127.0.0.1:5900
```

Remote VNC with a verified X509 VeNCrypt certificate:

```sh
rdp2vnc linux.example:5900 --vnc-ca ./vnc-ca.pem
```

A trusted VPN carrying macOS VNC, with explicit consent to the application's unencrypted VNC leg:

```sh
rdp2vnc mac.local:5900 --username user --allow-insecure-vnc
```

A Mac configured with the separate legacy VNC-viewer password instead of ARD:

```sh
rdp2vnc 127.0.0.1:5900 --ssh user@mac.local --auth vnc
```

Classic VNC passwords are limited to **eight ASCII bytes**; longer passwords are rejected rather than silently truncated. Use ARD for Mac account passwords (at most 63 UTF-8 bytes under that protocol). An unencrypted VPN/LAN exception does not enable legacy or unauthenticated RDP.

To run the bridge on a different machine, bind explicitly to its VPN address, then connect mstsc to that address:

```sh
rdp2vnc 127.0.0.1:5900 --listen 100.64.0.10:3390 --allow-remote
```

The example address must be replaced with an address actually assigned to your host. Never expose this initial implementation directly to the Internet. The default is **127.0.0.1:3390**, so it neither competes with system port 3389 nor opens a network-wide listener accidentally.

## Passwords and automation

Plaintext password arguments/credential-bearing URLs are deliberately unsupported. Use masked prompts, environment variables `RDP2VNC_VNC_PASSWORD` / `RDP2VNC_RDP_PASSWORD`, or UTF-8 files:

```sh
rdp2vnc 127.0.0.1:5900 \
  --vnc-password-file /private/vnc-password \
  --rdp-password-file /private/rdp-password
```

Password files are **not** the encrypted `.vnc/passwd` format. On Unix, use mode 0600 or stricter; on Windows, restrict the file/directory ACL to your account. Environment variables can be inspected by sufficiently privileged processes; secret files or an interactive prompt are preferable. RDP passwords must contain at least 12 bytes. Non-interactive operation never generates a password into redirected logs.

TLS identities are generated once per user, reused, and never overwritten silently. New identities are staged privately and published as a complete pair under `tls/identity`; an interrupted first creation can safely retry. Existing legacy pairs remain in use. An incomplete existing identity requires restoring its missing file or explicitly supplying `--cert`/`--key`, so trusted fingerprints are never silently changed. Generated keys use private permissions on Unix and the per-user application data directory on Windows. Generated certificates expire after one year; certificate rotation and Windows ACL policy are operator responsibilities. `SSLKEYLOGFILE` is deliberately not enabled. `RUST_LOG` is not honored, because upstream debug output may contain credentials; use `RDP2VNC_LOG=debug` for application-only diagnostics.

## Useful options

| Option | Purpose |
| --- | --- |
| `--probe` | Authenticate to VNC and report its size/security without opening RDP |
| `--read-only` | Block RDP keyboard and mouse forwarding |
| `--fps 20` | Maximum VNC update-request frequency, not a promised frame rate |
| `--keymap auto\|pc\|mac` | US scan-code mapping; Mac Command/Option/Control distinctions |
| `--auth auto\|vnc\|ard\|none` | Explicit authentication policy; auto never falls back to None |
| `--rdp-file desktop.rdp` | Generate a password-free mstsc profile without overwriting a file |
| `--help` | Complete options and validation constraints |

Generated `.rdp` profiles require a trusted server identity (`authentication level:i:1`) and disable unsupported clipboard/audio redirection. With the default self-signed certificate, establish trust first or supply a CA-issued certificate. No certificate verification bypass is generated.

## Implemented scope

RDP TLS 1.2/1.3 plus NLA/CredSSP, independent gateway credentials, bounded authentication time, one active authenticated RDP client, up to eight pending handshakes, and immediate rejection of new clients while the desktop is occupied. A reconnecting RDP client receives a complete framebuffer snapshot. A lost VNC connection closes the gateway cleanly instead of continuing to show a stale desktop.

RFB 3.3/3.7/3.8, Apple's 3.889 version banner, classic VNC authentication, ARD authentication, explicit None authentication on a protected/acknowledged transport, X509 VeNCrypt 0.2, and system OpenSSH forwarding. Encodings: Raw, CopyRect, Hextile, ZRLE; DesktopSize and LastRect pseudo-encodings. Bounded dimensions/lengths, full-width 4K updates, overlap-safe CopyRect, coalesced snapshots, keyboard/mouse, and UTF-16 to Unicode keysym translation.

**Not implemented:** clipboard synchronization (including Chinese copy/paste), file/audio/drive/USB redirection, multi-monitor topology, client-requested backend resolution changes, Tight/JPEG or H.264 codecs, Apple's high-performance screen-sharing protocol, VNC backend auto-reconnect, and non-US scan-code layouts. Unicode input support is not the same as an end-to-end guarantee for every Mac input method. Limits: 8192 pixels per side and 16,777,216 total pixels; 4K and 5K fit, 6K/8K desktops above that pixel budget are rejected explicitly.

## Development

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

Linux integration additionally uses a real FreeRDP client against an independent loopback RFB fixture under Xvfb. It checks NLA rejection, rendered pixel colors, keyboard/mouse forwarding, concurrent-client rejection, reconnect snapshots, and clean backend EOF. Inspect the CI result for the **exact commit**; the existence of a test is not evidence that it passed.

See [architecture](docs/architecture.md), [security](SECURITY.md), and [contributing](CONTRIBUTING.md). The implementation is Apache-2.0 licensed. Earlier RDP/VNC projects informed requirements; no C/Java source was mechanically copied or wrapped.
