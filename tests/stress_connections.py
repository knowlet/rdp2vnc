#!/usr/bin/env python3
"""Linux-only loopback admission/socket reclamation stress; no real desktops."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile

from e2e_freerdp import Fixture, stop, until


def main() -> None:
    fixture = Fixture()
    gateway = None
    peers = []
    with tempfile.TemporaryDirectory(prefix="rdp2vnc-stress-") as directory:
        root = Path(directory)
        log = root / "gateway.log"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        try:
            with log.open("w") as output:
                gateway = subprocess.Popen([
                    "target/debug/rdp2vnc", f"127.0.0.1:{fixture.port}",
                    "--auth", "none", "--listen", f"127.0.0.1:{port}",
                ], env=dict(os.environ, XDG_DATA_HOME=str(root / "data"),
                            RDP2VNC_RDP_PASSWORD="fixture-only-stress-password"),
                    stdout=output, stderr=subprocess.STDOUT)
            until(lambda: "RDP ready" in log.read_text(), "gateway failed to start")
            fd_path = Path(f"/proc/{gateway.pid}/fd")
            count_fds = lambda: len(list(fd_path.iterdir()))
            baseline = count_fds()
            peak = baseline
            for _ in range(100):
                for _ in range(8):
                    peers.append(socket.create_connection(("127.0.0.1", port), timeout=3))
                until(lambda: count_fds() == baseline + 8, "pending handshakes not accepted", 5)
                peak = max(peak, count_fds())
                with socket.create_connection(("127.0.0.1", port), timeout=3) as extra:
                    assert extra.recv(1) == b"", "ninth idle handshake was not rejected"
                for peer in peers:
                    peer.close()
                peers.clear()
                until(lambda: count_fds() == baseline, "closed peer descriptors leaked", 5)
            with socket.create_connection(("127.0.0.1", port), timeout=35) as idle:
                assert idle.recv(1) == b"", "idle handshake survived its deadline"
            until(lambda: count_fds() == baseline, "timed-out peer descriptor leaked", 5)
            assert gateway.poll() is None
            assert not fixture.errors, fixture.errors
            print(f"PASS: 800 idle handshakes reclaimed; 100 excess peers rejected; "
                  f"30s timeout reclaimed; descriptors baseline={baseline}, peak={peak}, final={count_fds()}")
        finally:
            for peer in peers:
                peer.close()
            if gateway is not None:
                stop(gateway)
            fixture.close()


if __name__ == "__main__":
    main()
