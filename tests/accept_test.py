#!/usr/bin/env python3
"""portico accept-gate test: a blacklisted IP is dropped at accept time.

Run against http_server booted with DENY_IP=127.0.0.1 (so on_accept rejects the
loopback peer). A connection is accepted at TCP then immediately closed by
portico before any handshake — so a request gets no response.
Usage: accept_test.py ws://127.0.0.1:<port>/
"""
import socket, sys
from urllib.parse import urlparse


def main():
    u = urlparse(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/")
    host, port = u.hostname or "127.0.0.1", u.port or 8080
    print(f"== portico accept-gate harness -> {host}:{port} (DENY_IP=127.0.0.1) ==")

    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(5)
        try:
            data = s.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError):
            data = b""
        s.close()
    except OSError as e:
        data = b""                 # connection refused/reset == denied
        print(f"  (socket: {e})")

    denied = (data == b"")
    print(f"  {'ok' if denied else 'FAIL'}  denied IP gets no response "
          f"(received {len(data)} bytes)")
    print(f"\n{'PASS' if denied else 'FAIL'}")
    return 0 if denied else 1


if __name__ == "__main__":
    sys.exit(main())
