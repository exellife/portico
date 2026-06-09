#!/usr/bin/env python3
"""portico HTTP/1.1 adversarial harness (raw sockets, full byte control).

Drives the http_server example: routing, status codes, keep-alive, pipelining,
partial/byte-at-a-time delivery, body framing, malformed requests, oversized
header/body, large-body round-trip, and concurrency.

CRITICAL findings (wrong status/body, crash, hang) fail the run.
"""
import socket, sys, threading, time
from urllib.parse import urlparse


class HTTP:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data if isinstance(data, bytes) else data.encode())

    def _fill(self):
        d = self.sock.recv(65536)
        if not d:
            raise ConnectionError("closed")
        self.buf += d

    def recv_response(self):
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest
        lines = head.split(b"\r\n")
        status = int(lines[0].split(b" ")[1])
        headers = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode()] = v.strip().decode()
        clen = int(headers.get("content-length", "0"))
        while len(self.buf) < clen:
            self._fill()
        body = self.buf[:clen]
        self.buf = self.buf[clen:]
        return status, headers, body

    def close(self):
        try: self.sock.close()
        except OSError: pass


class R:
    def __init__(self): self.ok = 0; self.warn = 0; self.crit = 0
    def check(self, name, cond, detail="", critical=True):
        tag = "ok" if cond else ("FAIL" if critical else "WARN")
        if cond: self.ok += 1
        elif critical: self.crit += 1
        else: self.warn += 1
        print(f"  {tag:<5} {name:<32} {detail}")
        return cond


def req(method, path, host="127.0.0.1", body=b"", extra="", version="1.1"):
    if isinstance(body, str): body = body.encode()
    head = f"{method} {path} HTTP/{version}\r\nHost: {host}\r\n{extra}"
    if body:
        head += f"Content-Length: {len(body)}\r\n"
    head += "\r\n"
    return head.encode() + body


def section(t): print(f"\n# {t}")


def main(host, port):
    r = R()
    print(f"== portico HTTP harness -> {host}:{port} ==")

    section("routing & status codes")
    c = HTTP(host, port)
    c.send(req("GET", "/")); s, h, b = c.recv_response()
    r.check("GET / -> 200", s == 200 and b"portico" in b)
    r.check("Content-Length correct", int(h["content-length"]) == len(b))
    c.send(req("GET", "/health")); s, h, b = c.recv_response()
    r.check("GET /health json", s == 200 and b == b'{"status":"ok"}'
            and h.get("content-type", "").startswith("application/json"))
    c.send(req("GET", "/missing")); s, h, b = c.recv_response()
    r.check("GET /missing -> 404", s == 404)
    c.send(req("DELETE", "/echo")); s, h, b = c.recv_response()
    r.check("DELETE /echo -> 405", s == 405 and "allow" in h)
    c.close()

    section("keep-alive & pipelining")
    c = HTTP(host, port)
    for i in range(5):
        c.send(req("GET", "/health")); s, h, b = c.recv_response()
        if s != 200: r.check(f"keep-alive req {i}", False); break
    else:
        r.check("5 requests on one connection", True)
    # pipelined: two requests in a single write
    c.send(req("GET", "/health") + req("GET", "/"))
    s1, _, b1 = c.recv_response(); s2, _, b2 = c.recv_response()
    r.check("pipelined requests", s1 == 200 and s2 == 200 and b"portico" in b2)
    c.close()

    section("body framing")
    c = HTTP(host, port)
    payload = b"x" * 5000
    c.send(req("POST", "/echo", body=payload)); s, h, b = c.recv_response()
    r.check("POST /echo body round-trip", s == 200 and b == payload)
    # body delivered in two writes
    head = req("POST", "/echo", body=b"")[:-0] if False else None
    body = b"split-body-test"
    raw = f"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n".encode()
    c.send(raw[:20]); time.sleep(0.05); c.send(raw[20:] + body[:5]); time.sleep(0.05); c.send(body[5:])
    s, h, b = c.recv_response()
    r.check("split request+body", s == 200 and b == body)
    c.close()

    section("transport robustness")
    # byte-at-a-time full request
    c = HTTP(host, port)
    raw = req("GET", "/health")
    for byte in raw:
        c.send(bytes([byte])); time.sleep(0.001)
    s, h, b = c.recv_response()
    r.check("byte-at-a-time request", s == 200 and b == b'{"status":"ok"}')
    c.close()

    section("error handling")
    c = HTTP(host, port)
    c.send(b"!!! totally bogus request \r\n\r\n")
    try:
        s, h, b = c.recv_response(); r.check("malformed -> 400", s == 400, f"got {s}")
    except Exception as e:
        r.check("malformed -> 400", False, repr(e))
    c.close()
    # oversized Content-Length -> 413 (no body actually sent)
    c = HTTP(host, port)
    c.send(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n")
    try:
        s, h, b = c.recv_response(); r.check("oversized body -> 413", s == 413, f"got {s}")
    except Exception as e:
        r.check("oversized body -> 413", False, repr(e))
    c.close()
    # oversized headers, no terminator -> 431 then close
    c = HTTP(host, port)
    c.send(b"GET / HTTP/1.1\r\nX-Big: " + b"A" * 40000)
    try:
        s, h, b = c.recv_response(); r.check("oversized headers -> 431", s == 431, f"got {s}")
    except Exception as e:
        r.check("oversized headers -> 431", False, repr(e))
    c.close()

    section("HTTP/1.0 default close")
    c = HTTP(host, port)
    c.send(req("GET", "/health", version="1.0")); s, h, b = c.recv_response()
    r.check("HTTP/1.0 Connection: close", h.get("connection", "").lower() == "close", h.get("connection"))
    c.close()

    section("large body round-trip")
    c = HTTP(host, port)
    big = bytes((i * 7) & 0xFF for i in range(500_000))
    c.send(req("POST", "/echo", body=big)); s, h, b = c.recv_response()
    r.check("500KB POST round-trip", s == 200 and b == big, f"got {len(b)} bytes")
    c.close()

    section("concurrency")
    errs = []
    def worker(i):
        try:
            cc = HTTP(host, port)
            for _ in range(20):
                cc.send(req("GET", "/health")); s, _, b = cc.recv_response()
                if s != 200 or b != b'{"status":"ok"}': errs.append(f"w{i}"); break
            cc.close()
        except Exception as e:
            errs.append(f"w{i}:{e!r}")
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
    t0 = time.time()
    for t in ts: t.start()
    for t in ts: t.join()
    r.check("30 conns x 20 reqs", not errs, f"{600} reqs in {time.time()-t0:.2f}s" if not errs else errs[0])

    print(f"\n== summary: {r.ok} ok, {r.warn} warn, {r.crit} critical ==")
    sys.exit(1 if r.crit else 0)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/"
    u = urlparse(url)
    main(u.hostname or "127.0.0.1", u.port or 8080)
