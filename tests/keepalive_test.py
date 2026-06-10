#!/usr/bin/env python3
"""portico keepalive + idle-reaping test (finding H-8).

Booted against http_server with PING_INTERVAL=1, PONG_TIMEOUT=1. Verifies the
once-dead ping_interval/pong_timeout config now does something:
  A. an idle OPEN WebSocket is PINGed by the server;
  B. a peer that answers the PING (or sends any data) stays connected;
  C. a peer that goes silent after the PING is reaped within pong_timeout;
  D. an idle HTTP keep-alive connection is reaped past ping_interval+pong_timeout.
Usage: keepalive_test.py ws://127.0.0.1:<port>/
"""
import base64, os, socket, struct, sys, time
from urllib.parse import urlparse

WS_BIN, WS_CLOSE, WS_PING, WS_PONG = 0x2, 0x8, 0x9, 0xA


class WS:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout); self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                           f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            d = self.sock.recv(4096)
            if not d: raise ConnectionError("handshake closed")
            resp += d
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            raise ConnectionError("handshake failed")
        self.buf = resp.split(b"\r\n\r\n", 1)[1]

    def send(self, opcode, payload=b""):
        n = len(payload); mk = os.urandom(4)
        out = bytes([0x80 | opcode]) + bytes([0x80 | n]) + mk + bytes(payload[i] ^ mk[i % 4] for i in range(n))
        self.sock.sendall(out)

    def recv_frame(self, timeout=6):
        self.sock.settimeout(timeout)
        def need(k):
            while len(self.buf) < k:
                d = self.sock.recv(1 << 16)
                if not d: raise ConnectionError("closed")
                self.buf += d
        need(2); ln = self.buf[1] & 0x7F; off = 2
        if ln == 126: need(4); ln = struct.unpack("!H", self.buf[2:4])[0]; off = 4
        need(off + ln)
        op = self.buf[0] & 0x0F; pay = self.buf[off:off + ln]; self.buf = self.buf[off + ln:]
        return op, pay

    def close(self):
        try: self.sock.close()
        except OSError: pass


def main(host, port):
    fails = 0
    def chk(n, cond, d=""):
        nonlocal fails
        print(f"  {'ok' if cond else 'FAIL':<5} {n:<46} {d}"); fails += (not cond)

    print(f"== portico keepalive harness -> {host}:{port} (ping=1s pong=1s) ==")

    # A+B: idle OPEN socket gets a PING; answering it keeps the connection alive.
    try:
        ws = WS(host, port)
        op, _ = ws.recv_frame(timeout=5)         # expect a server PING while idle
        chk("idle WS receives server PING", op == WS_PING, f"opcode={op}")
        ws.send(WS_PONG)                         # answer it
        ws.send(WS_BIN, b"still-here")           # ...and prove the socket still works
        # skip any further PING frames, find our echo
        got = None
        for _ in range(4):
            o, p = ws.recv_frame(timeout=5)
            if o == WS_BIN: got = p; break
        chk("answered peer stays connected (echo)", got == b"still-here", repr(got))
        ws.close()
    except Exception as e:
        chk("idle WS receives server PING", False, f"{e!r}")

    # C: a peer that ignores the PING is reaped within pong_timeout.
    try:
        ws = WS(host, port)
        t0 = time.time(); closed = False
        # read frames but never PONG; expect a CLOSE or EOF once pong_timeout lapses
        try:
            for _ in range(6):
                o, _ = ws.recv_frame(timeout=6)
                if o == WS_CLOSE: closed = True; break
        except (ConnectionError, socket.timeout):
            closed = True
        dt = time.time() - t0
        chk("silent peer reaped after PING", closed and dt < 6, f"{dt:.1f}s")
        ws.close()
    except Exception as e:
        chk("silent peer reaped after PING", False, f"{e!r}")

    # D: an idle HTTP keep-alive connection is reaped past ping_interval+pong_timeout.
    try:
        s = socket.create_connection((host, port), timeout=10); s.settimeout(8)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode())
        _ = s.recv(4096)                          # consume the response, then go idle
        t0 = time.time()
        try:
            reaped = (s.recv(64) == b"")          # server closes -> clean EOF
        except (ConnectionError, socket.timeout):
            reaped = True
        dt = time.time() - t0
        chk("idle HTTP keep-alive reaped", reaped and dt < 7, f"{dt:.1f}s")
        s.close()
    except Exception as e:
        chk("idle HTTP keep-alive reaped", False, f"{e!r}")

    print("\nPASS" if fails == 0 else "\nFAIL")
    return 1 if fails else 0


if __name__ == "__main__":
    u = urlparse(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/")
    sys.exit(main(u.hostname or "127.0.0.1", u.port or 8080))
