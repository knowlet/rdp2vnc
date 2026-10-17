#!/usr/bin/env python3
"""Loopback-only FreeRDP/NLA -> bridge -> independent RFB fixture test.

Run under xvfb-run on Linux after cargo build --locked. Requires FreeRDP 3,
xdotool, and Pillow; --legacy-identity also requires OpenSSL. The throwaway
password and /cert:ignore are ONLY for this isolated fixture, never production
connection examples. No real desktop or
credentials are accessed. This is not a substitute for physical mstsc/macOS QA.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

from PIL import ImageGrab


def receive(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("RFB peer disconnected")
        data.extend(chunk)
    return bytes(data)


class Fixture:
    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.events: list[tuple] = []
        self.errors: list[Exception] = []
        self.connection: socket.socket | None = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        try:
            with self.listener.accept()[0] as sock:
                self.connection = sock
                sock.settimeout(90)
                sock.sendall(b"RFB 003.889\n")
                assert receive(sock, 12) == b"RFB 003.008\n"
                sock.sendall(b"\x01\x01")
                assert receive(sock, 1) == b"\x01"
                sock.sendall(struct.pack(">I", 0))
                assert receive(sock, 1) == b"\x01", "must share, never evict other viewers"
                fmt = struct.pack(">BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
                sock.sendall(struct.pack(">HH", 640, 480) + fmt + struct.pack(">I", 7) + b"fixture")
                sent = False
                while True:
                    kind = receive(sock, 1)[0]
                    if kind == 0:
                        receive(sock, 19)
                    elif kind == 2:
                        count = struct.unpack(">xH", receive(sock, 3))[0]
                        assert count <= 32
                        receive(sock, count * 4)
                    elif kind == 3:
                        request = receive(sock, 9)
                        incremental = request[0]
                        if not sent or not incremental:
                            rect = struct.pack(">HHHHi", 0, 0, 640, 480, 0)
                            # BGRX -> expected displayed RGB = (73, 149, 211).
                            sock.sendall(b"\x00\x00\x00\x01" + rect + bytes((211, 149, 73, 0)) * (640 * 480))
                            sent = True
                        else:
                            sock.sendall(b"\x00\x00\x00\x00")
                    elif kind == 4:
                        down, keysym = struct.unpack(">B2xI", receive(sock, 7))
                        self.events.append(("key", down, keysym))
                    elif kind == 5:
                        mask, x, y = struct.unpack(">BHH", receive(sock, 5))
                        self.events.append(("pointer", mask, x, y))
                    else:
                        raise AssertionError(f"unexpected RFB message {kind}")
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(error)

    def close(self) -> None:
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.thread.join(timeout=3)


def until(predicate, message: str, timeout: float = 25) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(message)


def visible_frame() -> bool:
    image = ImageGrab.grab().convert("RGB")
    colors = image.getcolors(image.width * image.height) or []
    return any(count > 100_000 and all(abs(a - b) <= 3 for a, b in zip(rgb, (73, 149, 211)))
               for count, rgb in colors)


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-identity", action="store_true",
                        help="test an explicit .crt/.key identity with a throwaway PKCS#8 key")
    args = parser.parse_args()
    client = shutil.which("xfreerdp3") or shutil.which("xfreerdp")
    assert client, "install freerdp3-x11"
    fixture = Fixture()
    processes: list[subprocess.Popen] = []
    stalled: socket.socket | None = None
    with tempfile.TemporaryDirectory(prefix="rdp2vnc-e2e-") as temporary:
        root = Path(temporary)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = dict(os.environ, XDG_DATA_HOME=str(root / "data"),
                   RDP2VNC_RDP_PASSWORD="fixture-only-good-password")
        gateway_log = root / "gateway.log"
        identity_args: list[str] = []
        identity_files: list[tuple[Path, bytes]] = []
        try:
            if args.legacy_identity:
                openssl = shutil.which("openssl")
                assert openssl, "install openssl for --legacy-identity"
                cert_path, key_path = root / "server.crt", root / "server.key"
                subprocess.run([
                    openssl, "req", "-x509", "-newkey", "ec",
                    "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-subj", "/CN=localhost", "-days", "1",
                    "-keyout", str(key_path), "-out", str(cert_path),
                ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
                key_path.chmod(0o600)
                key_bytes = key_path.read_bytes()
                assert key_bytes.startswith(b"-----BEGIN PRIVATE KEY-----\n"), \
                    "legacy fixture must use an unencrypted PKCS#8 PRIVATE KEY"
                identity_files = [(cert_path, cert_path.read_bytes()), (key_path, key_bytes)]
                identity_args = ["--cert", str(cert_path), "--key", str(key_path)]
            with gateway_log.open("w") as output:
                gateway = subprocess.Popen([
                    "target/debug/rdp2vnc", f"127.0.0.1:{fixture.port}",
                    "--auth", "none", "--listen", f"127.0.0.1:{port}",
                    "--rdp-username", "ci", "--fps", "10",
                ] + identity_args, env=env, stdout=output, stderr=subprocess.STDOUT)
            processes.append(gateway)
            until(lambda: "RDP ready" in gateway_log.read_text(), "gateway did not become ready")
            # A peer that never sends even X.224 must not reserve the desktop.
            stalled = socket.create_connection(("127.0.0.1", port), timeout=3)
            common = [client, f"/v:127.0.0.1:{port}", "/u:ci", "/cert:ignore", "/sec:nla",
                      "/size:640x480", "/bpp:32", "/gdi:sw", "/log-level:INFO"]
            wrong = subprocess.run(common + ["/p:fixture-only-wrong-password"], env=env,
                                   capture_output=True, text=True, timeout=25)
            (root / "rejected.log").write_text(wrong.stdout + wrong.stderr)
            assert wrong.returncode != 0, "invalid NLA credentials were accepted"
            assert any(word in wrong.stdout + wrong.stderr for word in
                       ("LOGON_FAILURE", "AUTHENTICATION_FAILED", "STATUS_LOGON_FAILURE")), "failure was not an NLA authentication rejection"
            time.sleep(0.5)
            for attempt in range(2):
                with (root / f"client-{attempt}.log").open("w") as output:
                    viewer = subprocess.Popen(common + ["/p:fixture-only-good-password"], env=env,
                                              stdout=output, stderr=subprocess.STDOUT)
                processes.append(viewer)
                until(visible_frame, "RDP framebuffer did not match the VNC fixture while an unauthenticated peer was idle", timeout=12)
                assert viewer.poll() is None, "RDP client exited prematurely"
                if attempt == 0:
                    ids = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--pid", str(viewer.pid)], text=True).split()
                    assert ids, "no FreeRDP window"
                    window = ids[-1]
                    subprocess.run(["xdotool", "windowfocus", "--sync", window], check=True)
                    subprocess.run(["xdotool", "mousemove", "--window", window, "123", "117", "click", "1", "key", "a"], check=True)
                    until(lambda: ("key", 1, 97) in fixture.events and ("key", 0, 97) in fixture.events,
                          "RDP key press/release did not reach VNC")
                    until(lambda: any(e[0] == "pointer" and e[1] & 1 for e in fixture.events),
                          "RDP mouse button did not reach VNC")
                    # An unsuccessful contender's disconnect must not reset
                    # keys held by the admitted client.
                    subprocess.run(["xdotool", "keydown", "b"], check=True)
                    until(lambda: ("key", 1, 98) in fixture.events, "held key did not reach VNC")
                    checkpoint = len(fixture.events)
                    assert stalled is not None
                    stalled.close()
                    stalled = None
                    time.sleep(0.5)
                    assert ("key", 0, 98) not in fixture.events[checkpoint:], "unauthenticated disconnect released the active client's key"
                    subprocess.run(["xdotool", "keyup", "b"], check=True)
                    until(lambda: ("key", 0, 98) in fixture.events[checkpoint:], "held key release did not reach VNC")
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as extra:
                        extra.settimeout(3)
                        assert extra.recv(1) == b"", "second simultaneous RDP client was not rejected"
                stop(viewer)
                time.sleep(0.7)
            fixture.close()
            gateway.wait(timeout=5)
            assert gateway.returncode not in (0, 101), "backend disconnect should fail cleanly, not panic or succeed"
            assert "panicked at" not in gateway_log.read_text()
            assert not fixture.errors, fixture.errors
            for path, original in identity_files:
                assert path.read_bytes() == original, f"{path.name} changed during the test"
            identity_mode = "legacy .crt/.key identity" if args.legacy_identity else "generated .pem identity"
            print(f"PASS: {identity_mode}; idle-peer admission; NLA rejection; authenticated pixels; keyboard/mouse; unsuccessful-peer input isolation; concurrent-client rejection; late-client snapshot; clean VNC EOF")
        finally:
            if stalled is not None:
                stalled.close()
            for process in reversed(processes):
                stop(process)
            fixture.close()
            for path in sorted(root.glob("*.log")):
                print(f"--- {path.name} ---\n{path.read_text(errors='replace')[-16000:]}")


if __name__ == "__main__":
    main()
