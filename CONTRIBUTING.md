# Contributing

Target `develop` through a feature branch and a pull request. Do not commit credentials, certificates/private keys, captured private desktops, or local configuration. Use Conventional Commits, for example `feat(rfb): add ExtendedClipboard negotiation`, `fix(input): preserve modifier releases`, or `test: cover fragmented authentication`.

Before requesting merge:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
```

Keep `Cargo.lock` committed for the executable. Update the immutable IronRDP revision deliberately, reviewing its APIs and security behavior; do not substitute an unverified floating Git branch. Never silence protocol/security test failures or relax TLS/NLA defaults to make a client connect.

Advertise only implemented RFB/RDP capabilities. Add malformed-input, length/overflow, fragmented-network, disconnect, and authentication-downgrade tests alongside new functionality. Document practical limits and unrun interoperability tests. Native macOS CI compilation is not proof that a physical macOS Screen Sharing server works.

The Linux loopback integration test uses FreeRDP, Xvfb, xdotool, and Pillow. Install those test-only tools, run `cargo build --locked`, then:

```sh
xvfb-run -a -s '-screen 0 1024x768x24' /usr/bin/python3 tests/e2e_freerdp.py
```

Its disposable credentials and certificate bypass are confined to local fixtures. Never reuse them in production examples. New .rdp profiles must not include a password or disable server identity verification.
