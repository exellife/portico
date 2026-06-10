#!/usr/bin/env python3
"""portico slowloris-reaper test (finding H-7).

Run against http_server booted with HANDSHAKE_TIMEOUT=1. Verifies:
  (1) a connection that stalls in the pre-request (CONNECTING) state IS reaped
      shortly after the deadline — the reorder didn't disable the reaper;
  (2) reaping is safe under load: many stalled connections are reaped, some
      dribbling a byte right at the deadline so an EPOLLIN lands in the same
      epoll batch the reaper sweeps in, while many legitimate WS echo
      connections churn fd numbers concurrently. Every legit echo must succeed
      and the server must stay up.

Pre-fix the reaper ran BEFORE the event loop: a stalled fd that both timed out
and had a queued event in the same batch was closed+freed by the reaper, then
re-closed by the loop via its now-stale event — a double close(2) that, once the
acceptor reused that fd number, tore down an unrelated live connection.
Usage: reaper_test.py ws://127.0.0.1:<port>/
"""
import base64, hashlib, os, socket, struct, sys, threading, time
from urllib.parse import urlparse

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_BIN = 0x2


def ws_connect(host, port, timeout=10):
    s = socket.create_connection((host, port), timeout=timeout); s.settimeout(timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        d = s.recv(4096)
        if not d:
            raise ConnectionError("handshake closed")
        resp += d
    if b"101" not in resp.split(b"\r\n", 1)[0]:
        raise ConnectionError("handshake not 101")
    return s, resp.split(b"\r\n\r\n", 1)[1]


def ws_echo(host, port, payload):
    s, buf = ws_connect(host, port)
    n = len(payload); mk = os.urandom(4)
    hdr = bytes([0x80 | WS_BIN])
    if n < 126:      hdr += bytes([0x80 | n])
    elif n < 65536:  hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
    else:            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
    s.sendall(hdr + mk + bytes(payload[i] ^ mk[i % 4] for i in range(n)))
    while len(buf) < 2:
        buf += s.recv(4096)
    ln = buf[1] & 0x7F; off = 2
    if ln == 126:
        while len(buf) < 4:  buf += s.recv(4096)
        ln = struct.unpack("!H", buf[2:4])[0]; off = 4
    elif ln == 127:
        while len(buf) < 10: buf += s.recv(4096)
        ln = struct.unpack("!Q", buf[2:10])[0]; off = 10
    while len(buf) < off + ln:
        buf += s.recv(4096)
    out = buf[off:off + ln]
    s.close()
    return out


def main():
    u = urlparse(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/")
    host, port = u.hostname or "127.0.0.1", u.port or 8080
    print(f"== portico reaper harness -> {host}:{port} (HANDSHAKE_TIMEOUT=1) ==")
    fails = 0

    # (1) A silent, pre-request connection must be reaped after the deadline.
    s = socket.create_connection((host, port), timeout=10)  # CONNECTING, sends nothing
    s.settimeout(6)
    t0 = time.time()
    try:
        reaped = (s.recv(64) == b"")          # server closes -> clean EOF
    except (ConnectionResetError, socket.timeout):
        reaped = isinstance(sys.exc_info()[1], ConnectionResetError)
    dt = time.time() - t0
    s.close()
    ok = reaped and dt < 5
    print(f"  {'ok' if ok else 'FAIL'}  stalled connection reaped (after {dt:.1f}s)")
    fails += 0 if ok else 1

    # (2) Reap-under-load race: stalled conns (half dribble a byte at the deadline)
    #     reaped while legit echoers churn fd numbers. All echoes must succeed.
    stop = threading.Event()
    errors = []

    def staller(dribble):
        try:
            ss = socket.create_connection((host, port), timeout=10)  # silent -> CONNECTING
            if dribble:
                time.sleep(1.05)              # just past the 1s reap deadline
                try: ss.sendall(b"X")          # EPOLLIN lands near the reaper sweep
                except OSError: pass
            time.sleep(2.5)
            ss.close()
        except OSError:
            pass

    def echoer(wid):
        try:
            for j in range(12):
                if stop.is_set(): break
                p = f"w{wid}-m{j}-".encode() + os.urandom(120)
                if ws_echo(host, port, p) != p:
                    errors.append(f"w{wid}: echo mismatch at {j}"); return
        except Exception as e:
            errors.append(f"w{wid}: {e!r}")

    stallers = [threading.Thread(target=staller, args=(i % 2 == 0,)) for i in range(40)]
    echoers  = [threading.Thread(target=echoer, args=(i,)) for i in range(20)]
    for t in stallers + echoers: t.start()
    for t in echoers: t.join()
    stop.set()
    for t in stallers: t.join()

    ok2 = not errors
    print(f"  {'ok' if ok2 else 'FAIL'}  20 echoers x12 amid 40 reaped stalls"
          f"{'' if ok2 else ' :: ' + errors[0]}")
    fails += 0 if ok2 else 1

    # (3) Server must be healthy after the storm.
    try:
        alive = ws_echo(host, port, b"alive?") == b"alive?"
    except Exception as e:
        alive = False; print(f"  (alive probe: {e!r})")
    print(f"  {'ok' if alive else 'FAIL'}  server alive after reap storm")
    fails += 0 if alive else 1

    print(f"\n{'PASS' if fails == 0 else 'FAIL'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
