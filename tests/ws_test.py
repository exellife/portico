#!/usr/bin/env python3
"""portico WebSocket adversarial harness (raw-socket client, full frame control).

Drives the echo_server example: send a binary WS message, expect the identical
bytes echoed back. Probes payload-size boundaries, fragmentation, control frames,
RFC framing rules, partial/pipelined transport, and concurrency.

CRITICAL findings (wrong data, crash, hang) fail the run; RFC deviations are WARN.
"""
import base64, hashlib, os, socket, struct, sys, threading, time
from urllib.parse import urlparse

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_CONT, WS_TEXT, WS_BIN, WS_CLOSE, WS_PING, WS_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WS:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self._handshake(host, port)

    def _handshake(self, host, port):
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            d = self.sock.recv(4096)
            if not d:
                raise ConnectionError("handshake: connection closed")
            resp += d
        head, _, rest = resp.partition(b"\r\n\r\n")
        if b"101" not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"handshake failed: {head[:80]!r}")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        if accept.encode() not in head:
            raise ConnectionError("handshake: bad Sec-WebSocket-Accept")
        self.buf = rest

    def send_frame(self, opcode, payload=b"", fin=True, mask=True, rsv=0):
        b0 = (0x80 if fin else 0) | ((rsv & 0x7) << 4) | (opcode & 0xF)
        n = len(payload)
        out = bytes([b0]); mbit = 0x80 if mask else 0
        if n < 126:        out += bytes([mbit | n])
        elif n < 65536:    out += bytes([mbit | 126]) + struct.pack("!H", n)
        else:              out += bytes([mbit | 127]) + struct.pack("!Q", n)
        if mask:
            mk = os.urandom(4); out += mk
            payload = bytes(payload[i] ^ mk[i % 4] for i in range(n))
        self.sock.sendall(out + payload)

    def _need(self, k):
        while len(self.buf) < k:
            d = self.sock.recv(1 << 20)
            if not d:
                raise ConnectionError("recv: connection closed")
            self.buf += d

    def recv_frame(self, timeout=10):
        self.sock.settimeout(timeout)
        self._need(2)
        b0, b1 = self.buf[0], self.buf[1]
        fin, rsv, opcode = b0 >> 7, (b0 >> 4) & 0x7, b0 & 0xF
        masked, ln = b1 >> 7, b1 & 0x7F
        off = 2
        if ln == 126:   self._need(4);  ln = struct.unpack("!H", self.buf[2:4])[0]; off = 4
        elif ln == 127: self._need(10); ln = struct.unpack("!Q", self.buf[2:10])[0]; off = 10
        if masked: off += 4
        self._need(off + ln)
        payload = self.buf[off:off + ln]; self.buf = self.buf[off + ln:]
        return dict(fin=fin, rsv=rsv, opcode=opcode, masked=masked, payload=payload)

    def recv_data(self, timeout=10):
        while True:
            f = self.recv_frame(timeout)
            if f["opcode"] in (WS_BIN, WS_TEXT):
                return f
            if f["opcode"] == WS_CLOSE:
                raise ConnectionError("server sent CLOSE")

    def echo(self, payload):
        self.send_frame(WS_BIN, payload)
        return self.recv_data()

    def close(self):
        try: self.sock.close()
        except OSError: pass


class Results:
    def __init__(self): self.crit = 0; self.warn = 0; self.ok = 0
    def _p(self, tag, name, detail): print(f"  {tag:<5} {name:<34} {detail}")
    def ok_(self, n, d=""):   self.ok += 1;   self._p("ok", n, d)
    def warn_(self, n, d=""): self.warn += 1; self._p("WARN", n, d)
    def crit_(self, n, d=""): self.crit += 1; self._p("FAIL", n, d)
    def check(self, n, cond, d="", critical=True):
        (self.ok_ if cond else (self.crit_ if critical else self.warn_))(n, d); return cond


def section(t): print(f"\n# {t}")


def test_sizes(host, port, R):
    section("payload sizes (raw echo)")
    for n in [0, 1, 2, 125, 126, 127, 128, 1023, 1024, 1025, 4095, 4096, 4097,
              16383, 16384, 16385, 65535, 65536, 100000, 500000, 1000000]:
        payload = os.urandom(n)
        try:
            ws = WS(host, port); f = ws.echo(payload); ws.close()
            if f["masked"]:
                R.crit_(f"size {n}", "server masked a frame"); continue
            R.check(f"size {n}", f["payload"] == payload,
                    "" if f["payload"] == payload else f"len {len(f['payload'])}!={n}")
        except Exception as e:
            R.crit_(f"size {n}", f"{e!r}")


def test_over_limit(host, port, R):
    section("over-limit payload (>1MB)")
    try:
        ws = WS(host, port); ws.send_frame(WS_BIN, os.urandom(2_000_000))
        try:
            ws.recv_frame(timeout=4); R.warn_("over-limit", "server replied")
        except (ConnectionError, socket.timeout):
            R.ok_("over-limit handled", "closed/dropped")
        ws.close()
    except Exception as e:
        R.warn_("over-limit send", f"{e!r}")
    try:
        ws = WS(host, port); ok = ws.echo(b"alive?")["payload"] == b"alive?"; ws.close()
        R.check("server alive after over-limit", ok)
    except Exception as e:
        R.crit_("server alive after over-limit", f"{e!r}")


def test_length_overflow(host, port, R):
    section("declared-length overflow (C-1)")
    # Masked binary frame with a 64-bit declared length but only a 14-byte header
    # on the wire (2 + 8 length + 4 mask), no payload. The server must reject it
    # WITHOUT evaluating header_len + payload_len — that sum integer-overflows
    # size_t for 0xFFFF..FF (wraps below the bytes present), defeating the
    # completeness check and driving an unbounded out-of-bounds unmask write.
    cases = {
        "len=2^64-1 (wraps size_t)": b"\xff" * 8,
        "len=5MB (>max_message)":    struct.pack("!Q", 5_000_000),
    }
    for name, lenbytes in cases.items():
        try:
            ws = WS(host, port)
            ws.sock.sendall(bytes([0x80 | WS_BIN, 0x80 | 127]) + lenbytes + os.urandom(4))
            try:
                f = ws.recv_frame(timeout=4)
                R.check(f"{name} rejected", f["opcode"] == WS_CLOSE,
                        f"opcode={f['opcode']}", critical=False)
            except (ConnectionError, socket.timeout):
                R.ok_(f"{name} rejected", "connection dropped")
            ws.close()
        except Exception as e:
            R.ok_(f"{name} rejected", f"{e!r}")  # refused/reset on send is also rejection
    # The crux: the worker must not have crashed handling the overflow frame.
    try:
        ws = WS(host, port); ok = ws.echo(b"alive?")["payload"] == b"alive?"; ws.close()
        R.check("server alive after overflow frame", ok)
    except Exception as e:
        R.crit_("server alive after overflow frame", f"{e!r}")


def test_fragmentation(host, port, R):
    section("fragmentation")
    msg = b"fragmented-" + os.urandom(120)
    a, b, c = msg[:10], msg[10:40], msg[40:]
    try:
        ws = WS(host, port)
        ws.send_frame(WS_BIN, a, fin=False)
        ws.send_frame(WS_CONT, b, fin=False)
        ws.send_frame(WS_CONT, c, fin=True)
        got = ws.recv_data()["payload"]; ws.close()
        R.check("3-way fragmented echo", got == msg, f"len {len(got)}")
    except Exception as e:
        R.crit_("fragmented echo", f"{e!r}")


def test_control(host, port, R):
    section("control frames")
    try:
        ws = WS(host, port); tok = os.urandom(16); ws.send_frame(WS_PING, tok)
        f = ws.recv_frame()
        R.check("PING -> PONG", f["opcode"] == WS_PONG and f["payload"] == tok)
        ws.close()
    except Exception as e:
        R.crit_("ping/pong", f"{e!r}")
    try:
        ws = WS(host, port); ws.send_frame(WS_PONG, b"unsolicited")
        R.check("unsolicited PONG ignored", ws.echo(b"hi")["payload"] == b"hi"); ws.close()
    except Exception as e:
        R.crit_("unsolicited pong", f"{e!r}")
    try:
        ws = WS(host, port); ws.send_frame(WS_CLOSE, struct.pack("!H", 1000))
        f = ws.recv_frame(timeout=4)
        R.check("CLOSE -> CLOSE echo", f["opcode"] == WS_CLOSE, critical=False); ws.close()
    except (ConnectionError, socket.timeout) as e:
        R.warn_("CLOSE handshake", f"{e!r}")


def test_framing_rules(host, port, R):
    section("RFC framing rules")
    for name, kw in [("unmasked", dict(mask=False)),
                     ("reserved-bit", dict(rsv=0x4)),
                     ("invalid-opcode", dict())]:
        try:
            ws = WS(host, port)
            if name == "invalid-opcode":
                ws.send_frame(0xB, b"x")
            else:
                ws.send_frame(WS_BIN, b"x", **kw)
            try:
                f = ws.recv_frame(timeout=3)
                R.check(f"{name} rejected", f["opcode"] == WS_CLOSE,
                        f"opcode={f['opcode']}", critical=False)
            except (ConnectionError, socket.timeout):
                R.ok_(f"{name} rejected", "connection dropped")
            ws.close()
        except Exception as e:
            R.warn_(name, f"{e!r}")


def test_transport(host, port, R):
    section("transport robustness")
    payload = b"dribble-" + os.urandom(60); n = len(payload); mk = os.urandom(4)
    raw = bytes([0x80 | WS_BIN, 0x80 | n]) + mk + bytes(payload[i] ^ mk[i % 4] for i in range(n))
    try:
        ws = WS(host, port)
        for byte in raw:
            ws.sock.sendall(bytes([byte])); time.sleep(0.001)
        got = ws.recv_data()["payload"]; ws.close()
        R.check("byte-at-a-time frame", got == payload)
    except Exception as e:
        R.crit_("byte-at-a-time frame", f"{e!r}")
    try:
        ws = WS(host, port); blob = b""; msgs = [b"pipe0", b"pipe1", b"pipe2"]
        for m in msgs:
            mk = os.urandom(4)
            blob += bytes([0x80 | WS_BIN, 0x80 | len(m)]) + mk + bytes(m[i] ^ mk[i % 4] for i in range(len(m)))
        ws.sock.sendall(blob)
        got = [ws.recv_data()["payload"] for _ in msgs]; ws.close()
        R.check("pipelined frames", got == msgs, str(got))
    except Exception as e:
        R.crit_("pipelined frames", f"{e!r}")


def test_concurrency(host, port, R):
    section("concurrency")
    N, M = 40, 25; errors = []
    def worker(wid):
        try:
            ws = WS(host, port)
            for j in range(M):
                p = f"w{wid}-m{j}-".encode() + os.urandom(200)
                if ws.echo(p)["payload"] != p:
                    errors.append(f"w{wid}: mismatch {j}"); break
            ws.close()
        except Exception as e:
            errors.append(f"w{wid}: {e!r}")
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    t0 = time.time()
    for t in ts: t.start()
    for t in ts: t.join()
    R.check(f"{N} conns x {M} echoes", not errors,
            f"{N*M} msgs in {time.time()-t0:.2f}s" if not errors else errors[0])
    try:
        for _ in range(200):
            WS(host, port).close()
        R.check("200x connect/disconnect churn", WS(host, port).echo(b"ok")["payload"] == b"ok")
    except Exception as e:
        R.crit_("connect/disconnect churn", f"{e!r}")


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/"
    u = urlparse(url); host, port = u.hostname or "127.0.0.1", u.port or 8080
    R = Results()
    print(f"== portico WS harness -> {host}:{port} ==")
    for t in (test_sizes, test_over_limit, test_length_overflow, test_fragmentation,
              test_control, test_framing_rules, test_transport, test_concurrency):
        try: t(host, port, R)
        except Exception as e: R.crit_(t.__name__, f"harness error: {e!r}")
    print(f"\n== summary: {R.ok} ok, {R.warn} warn, {R.crit} critical ==")
    sys.exit(1 if R.crit else 0)


if __name__ == "__main__":
    main()
