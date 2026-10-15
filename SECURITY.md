# Security policy

This is a first implementation for controlled desktops, not a public multi-tenant gateway. Do not expose the RDP listener or a legacy VNC service directly to the Internet. Use loopback, an authenticated VPN, or SSH; restrict who can reach each endpoint.

The CLI always requires TLS plus NLA on RDP. Gateway and backend credentials are distinct. No password URL/argument, automatic certificate-ignore flag, TLS key logging, or dependency TRACE logging is enabled. A non-loopback RDP bind requires explicit consent. Plaintext remote VNC requires separate explicit consent. `--auth none` is never selected as an automatic fallback.

Certificate validation on the VNC X509 TLS leg includes the hostname. On the RDP side, clients must verify/trust the generated fingerprint or a CA-issued server identity. A self-signed certificate does not become trusted merely because TLS is enabled. SSH uses existing known_hosts and batch/key authentication, not trust-on-first-use automation.

On Unix, password files/private keys must not be group/world accessible. On Windows, operators must verify per-user directory and file ACLs. Secrets remain available to the running process and its privileged debuggers; zeroization is defense in depth, not a guarantee that all upstream allocations are wiped. ARD uses legacy crypto and non-constant-time big-integer operations for interoperability; protect it with authenticated SSH/TLS.

Length/dimension limits, bounded input queues, authentication deadlines, and fail-closed parsing reduce exposure but are not a substitute for a full security audit/fuzz campaign. An authenticated or explicitly trusted backend may still consume CPU or stall an in-progress update. Do not claim this initial release is independently audited or CVE-free.

For suspected security issues, use the repository's private vulnerability reporting feature if enabled. Do not attach passwords, private keys, real desktop screenshots, authentication traces, or exploit details to a public issue. Maintainers should arrange a private reporting channel before production deployment.
