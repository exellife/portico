#!/usr/bin/env python3
"""portico TLS regression test — HTTPS + WSS against one TLS listener.

Run via run_with_server.py against http_server (which speaks both HTTP and WS)
booted with TLS_CERT/TLS_KEY. Dependency-free: stdlib ssl + http.client and a
tiny raw WSS client, so it runs anywhere python3 does.
Usage: tls_test.py ws://127.0.0.1:<port>/   (host/port parsed; scheme ignored).
"""
import base64, http.client, os, socket, ssl, struct, sys
from urllib.parse import urlparse

ok = 0
fail = 0
def chk(name, cond, detail=""):
    global ok, fail
    print(f"  {'ok' if cond else 'FAIL':<5} {name:<28} {detail}")
    ok += bool(cond); fail += (not cond)


def https_get(host, port):
    ctx = ssl._create_unverified_context()
    c = http.client.HTTPSConnection(host, port, timeout=10, context=ctx)
    c.request("GET", "/")
    r = c.getresponse(); body = r.read(); c.close()
    return r.status, body


def _frame(opcode, payload):              # client frames must be masked
    n = len(payload)
    hdr = bytes([0x80 | opcode])
    if n < 126:      hdr += bytes([0x80 | n])
    elif n < 65536:  hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
    mask = os.urandom(4)
    return hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def _read_frame(s):
    def rd(n):
        d = b""
        while len(d) < n:
            c = s.recv(n - len(d))
            if not c: raise RuntimeError("closed")
            d += c
        return d
    b0, b1 = rd(2)
    op = b0 & 0x0F; ln = b1 & 0x7F
    if ln == 126:   ln = struct.unpack("!H", rd(2))[0]
    elif ln == 127: ln = struct.unpack("!Q", rd(8))[0]
    return op, (rd(ln) if ln else b"")


def wss_echo(host, port, payload=b"tls-echo-payload"):
    ctx = ssl._create_unverified_context()
    s = ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                        server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise RuntimeError("closed during WS handshake")
        buf += d
    status_line = buf.split(b"\r\n", 1)[0]
    s.sendall(_frame(0x2, payload))       # binary frame
    _op, data = _read_frame(s)
    s.close()
    return status_line, data


def main():
    u = urlparse(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/")
    host, port = u.hostname or "127.0.0.1", u.port or 8080
    print(f"== portico TLS harness -> {host}:{port} ==")

    try:
        status, body = https_get(host, port)
        chk("HTTPS GET 200", status == 200, str(status))
        chk("HTTPS body non-empty", len(body) > 0)
    except Exception as e:
        chk("HTTPS GET", False, repr(e))

    try:
        line, echoed = wss_echo(host, port)
        chk("WSS handshake 101", b"101" in line, line.decode(errors="replace"))
        chk("WSS binary echo", echoed == b"tls-echo-payload", repr(echoed))
    except Exception as e:
        chk("WSS echo", False, repr(e))

    print(f"\n{'PASS' if fail == 0 else 'FAIL'}  ({ok} ok, {fail} failed)")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
