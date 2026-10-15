# Compatibility and acceptance matrix

Keep test existence, test execution, and physical-device validation separate. The PR and CI status for the exact head commit are the execution record.

| Area | Implementation / automated coverage | Additional acceptance needed |
| --- | --- | --- |
| Linux / Windows / macOS executable | Native CI build, unit tests, Clippy, rustfmt | Packaged release binaries and signing |
| No-argument TUI | Masked setup form, cancellation/terminal cleanup paths | Manual terminal layout, resize, keyboard/IME checks on all platforms |
| RDP front end | IronRDP TLS 1.2/1.3 + NLA, independent credentials, loopback FreeRDP integration | Actual supported Windows mstsc builds, client security policies, certificate trust UX |
| Apple RFB version | Fragmented 3.889 banner fixture negotiates 3.8 | macOS releases, Screen Sharing vs Remote Management configuration |
| Apple ARD security type 30 | DH/AES response is independently decrypted in a server-side test fixture | Login window, account authorization, Unicode usernames/passwords on a physical Mac |
| RFB pixel encodings | Raw, CopyRect, Hextile, ZRLE, DesktopSize/LastRect; bounds/4K tests | TigerVNC/RealVNC/macOS real-server matrix and performance benchmarks |
| VNC transport | Strict OpenSSH; X509 VeNCrypt with trust roots and hostname verification; plaintext requires consent | Real SSH agent/Windows OpenSSH and private-CA deployment tests |
| Input | US scan codes, Command/Option/Control, Unicode surrogate pairs, original key-release mapping | Mac IME, modifier shortcuts, keyboard layout variants, scroll behavior |
| Reconnect | New RDP client gets complete current snapshot; VNC loss exits | Repeated physical-client disconnect/sleep/wake/load testing |
| Chinese clipboard | Not implemented; ServerCutText is bounded/discarded | Future ExtendedClipboard <-> CLIPRDR implementation and loop prevention |

## Physical Mac + mstsc checklist

1. Enable the selected macOS sharing service and authorize the intended user. Keep Screen Sharing and Remote Management configuration consistent with macOS requirements.
2. Establish trusted OpenSSH key/agent access to the same Mac. Run the gateway with loopback backend, `--ssh`, and `--username`; use `--probe` to isolate VNC authentication failures from RDP issues.
3. Run mstsc to the gateway on 3390. Verify the RDP certificate fingerprint and use the independent gateway credentials. Wrong RDP credentials must not reveal a desktop.
4. Exercise lock screen, active user desktop, 4K/5K display, resize, Command/Option/Control, Shift-release ordering, Unicode input, wheel, reconnect, and Ctrl+C cleanup.
5. Verify another VNC viewer is not evicted (shared mode), the extra RDP client is rejected, a slow/disconnected backend fails visibly, and no secrets appear in logs.
6. Record exact OS/client/server versions, resolution, authentication method, and transport. Do not label an unrun row 'supported/tested'.

Explicitly excluded in this version: Apple high-performance screen sharing, audio/video optimization claims, file/clipboard redirection, monitor topology management, and unlimited-resolution support.
