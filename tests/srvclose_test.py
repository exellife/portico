#!/usr/bin/env python3
"""portico server-initiated close teardown test (finding C-2).

Drives echo_server's "__srvclose__" hook, which makes the server call
ws_close_connection() -> process_close_message() — a teardown path no app
otherwise reaches. That path used to push the connection's pool slot onto the
free stack TWICE (double-free / slot aliasing) and never close(2) the fd. This
test forces many server-initiated closes interleaved with normal echo traffic so
slots are rapidly freed and reused: under the bug the aliasing corrupts a reused
connection (echo mismatch) or trips ASan's double-free; after the fix it's clean.
Usage: srvclose_test.py ws://127.0.0.1:<port>/
"""
import base64, hashlib, os, socket, struct, sys, threading, time
from urllib.parse import urlparse

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_BIN, WS_CLOSE = 0x2, 0x8


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
        out = bytes([0x80 | opcode])
        out += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
        out += mk + bytes(payload[i] ^ mk[i % 4] for i in range(n))
        self.sock.sendall(out)

    def recv_frame(self, timeout=5):
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

    # 1. a single server-initiated close emits a Close frame, then closes.
    try:
        ws = WS(host, port); ws.send(WS_BIN, b"__srvclose__")
        op, _ = ws.recv_frame(); ws.close()
        ok = (op == WS_CLOSE)
    except Exception as e:
        ok = False; print(f"  (srvclose: {e!r})")
    print(f"  {'ok' if ok else 'FAIL'}  server-initiated close emits CLOSE frame")
    fails += 0 if ok else 1

    # 2. churn: many server-closes interleaved with echoes, to reuse freed slots.
    errors = []
    def worker(wid):
        for i in range(40):
            if i % 2 == 0:
                # server-close trigger: the server RSTs us, so tolerate drop/timeout.
                try:
                    ws = WS(host, port); ws.send(WS_BIN, b"__srvclose__")
                    try: ws.recv_frame(timeout=4)
                    except (ConnectionError, socket.timeout): pass
                    ws.close()
                except Exception as e:
                    errors.append(f"w{wid}: close-path {e!r}")
            else:
                # echo MUST succeed and round-trip exactly. A reused slot that was
                # double-freed/aliased by C-2 corrupts this connection -> the echo
                # fails or mismatches. No tolerance here (loopback echoes are
                # reliable on a correct server).
                try:
                    ws = WS(host, port)
                    p = f"w{wid}-{i}-".encode() + os.urandom(80)
                    ws.send(WS_BIN, p)
                    op, pay = ws.recv_frame(timeout=4)
                    if not (op == WS_BIN and pay == p):
                        errors.append(f"w{wid}: echo bad (op={op}, match={pay == p}) — slot aliasing?")
                    ws.close()
                except Exception as e:
                    errors.append(f"w{wid}: echo-path {e!r}")
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    t0 = time.time()
    for t in ts: t.start()
    for t in ts: t.join()
    ok2 = not errors
    print(f"  {'ok' if ok2 else 'FAIL'}  20x40 close/echo churn clean "
          f"({time.time()-t0:.1f}s){'' if ok2 else ' :: ' + errors[0]}")
    fails += 0 if ok2 else 1

    # 3. the server is alive and correct after the churn.
    try:
        ws = WS(host, port); ws.send(WS_BIN, b"alive?")
        op, pay = ws.recv_frame(); ws.close()
        alive = (op == WS_BIN and pay == b"alive?")
    except Exception as e:
        alive = False; print(f"  (alive: {e!r})")
    print(f"  {'ok' if alive else 'FAIL'}  server alive after churn")
    fails += 0 if alive else 1

    print("\nPASS" if fails == 0 else "\nFAIL")
    return 1 if fails else 0


if __name__ == "__main__":
    u = urlparse(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/")
    sys.exit(main(u.hostname or "127.0.0.1", u.port or 8080))
