#!/usr/bin/env bash
# Static file serving (async): portico serves files from a docroot via the aio
# path — the read happens off the event thread and the response is produced from
# the read completion. Proves: correct bytes + Content-Type/Length, byte-exact
# large files, 404/403, traversal safety (encoded and plain), and keep-alive
# (multiple requests on ONE connection exercises the resume-after-completion path).
#   static_test.sh <http_server-binary>
set -euo pipefail

BIN="${1:?usage: static_test.sh <http_server-binary>}"
ROOT="$(mktemp -d)"
cleanup() { [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$ROOT"; }
trap cleanup EXIT

# Docroot fixture.
printf 'hello from portico static\n' > "$ROOT/hello.txt"
printf '<!doctype html><h1>hi</h1>'  > "$ROOT/index.html"
mkdir -p "$ROOT/assets"
printf 'body{color:red}'             > "$ROOT/assets/site.css"
head -c 250000 /dev/urandom          > "$ROOT/big.bin"
head -c 1500000 /dev/urandom         > "$ROOT/stream.bin"   # > 256KB → streamed (chunked)
python3 -c "open('$ROOT/f.txt','wb').write(bytes(range(256))*20)"   # 5120 predictable bytes
mkdir -p "$ROOT/sub" "$ROOT/noindex"
printf 'SUBDIR INDEX' > "$ROOT/sub/index.html"                     # directory index
# A symlink pointing outside the docroot must NOT be served.
ln -s /etc/passwd "$ROOT/escape.txt"

PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
STATIC_ROOT="$ROOT" PORT="$PORT" "$BIN" >/tmp/portico_static_srv.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do
  (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3>&-; break; }
  sleep 0.1
done

set +e   # capture the test exit codes ourselves below
PORT="$PORT" ROOT="$ROOT" python3 - <<'PY'
import http.client, os, sys, hashlib
PORT=int(os.environ["PORT"]); ROOT=os.environ["ROOT"]
ok=0; fail=0
def chk(name, cond, extra=""):
    global ok, fail
    print(f"  {'ok' if cond else 'FAIL':<5} {name} {extra}")
    ok+=bool(cond); fail+=(not cond)

def get(path, conn=None):
    c = conn or http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("GET", path)
    r = c.getresponse(); body = r.read()
    ct = r.getheader("Content-Type"); ka = r.getheader("Connection")
    if not conn: c.close()
    return r.status, body, ct, ka

def req_full(path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("GET", path, headers=headers or {})
    r = c.getresponse(); body = r.read()
    h = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, body, h

# existing text file
s,b,ct,_ = get("/hello.txt")
chk("text file 200 + bytes", s==200 and b==open(ROOT+"/hello.txt","rb").read(), f"status={s}")
chk("text/plain content-type", ct and ct.startswith("text/plain"), str(ct))

# nested + content-type by extension
s,b,ct,_ = get("/assets/site.css")
chk("nested file served", s==200 and b==b"body{color:red}")
chk("css content-type", ct=="text/css; charset=utf-8", str(ct))

s,_,ct,_ = get("/index.html")
chk("html content-type", ct and ct.startswith("text/html"), str(ct))

# large file byte-exact (async read into one buffer, sent via the backpressure path)
s,b,_,_ = get("/big.bin")
want = open(ROOT+"/big.bin","rb").read()
chk("250KB binary byte-exact",
    s==200 and hashlib.sha256(b).hexdigest()==hashlib.sha256(want).hexdigest(), f"status={s} len={len(b)}")

# not found
s,_,_,_ = get("/nope.txt"); chk("missing file -> 404", s==404, f"status={s}")

# traversal: encoded and (server sees it raw) — must not escape docroot
s,_,_,_ = get("/%2e%2e/%2e%2e/%2e%2e/etc/passwd"); chk("encoded traversal -> 403", s==403, f"status={s}")
s,_,_,_ = get("/../../../../etc/passwd");           chk("plain traversal blocked", s in (403,404), f"status={s}")
# symlink escaping the docroot must not be served
s,_,_,_ = get("/escape.txt");                       chk("symlink escape -> 403", s==403, f"status={s}")

# streamed file (> 256KB → chunked read↔send path), byte-exact
s,b,_,_ = get("/stream.bin")
want = open(ROOT+"/stream.bin","rb").read()
chk("1.5MB streamed byte-exact",
    s==200 and hashlib.sha256(b).hexdigest()==hashlib.sha256(want).hexdigest(), f"status={s} len={len(b)}")

# keep-alive: 3 requests on ONE connection — exercises resume-after-completion
c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
allok = True; ka_seen = True
for i in range(3):
    s,b,ct,ka = get("/hello.txt", conn=c)
    if s!=200 or b!=open(ROOT+"/hello.txt","rb").read(): allok=False
    if ka and ka.lower()=="close": ka_seen=False
c.close()
chk("keep-alive: 3 sequential on one conn", allok and ka_seen)

# keep-alive across a STREAMED response then a small one on one connection
c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
s1,b1,_,_ = get("/stream.bin", conn=c)
s2,b2,_,_ = get("/hello.txt", conn=c)
c.close()
chk("keep-alive after a streamed response",
    s1==200 and b1==want and s2==200 and b2==open(ROOT+"/hello.txt","rb").read())

# mid-stream client disconnect: start a big download, read a little, close abruptly.
# The server must release the in-flight stream cleanly and keep serving.
import socket
sk = socket.create_connection(("127.0.0.1", PORT), timeout=10)
sk.sendall(b"GET /stream.bin HTTP/1.1\r\nHost: x\r\n\r\n")
_ = sk.recv(4096)            # headers + a little body
sk.close()                   # abrupt close while the server is mid-stream
s,b,_,_ = get("/hello.txt")  # a fresh request still works → server survived
chk("survives mid-stream client disconnect", s==200 and b==open(ROOT+"/hello.txt","rb").read(), f"status={s}")

# concurrent streams: many simultaneous streamed downloads share the per-thread
# aio + EPOLLOUT coordination — all must come back byte-exact.
import threading
results = []
def worker():
    st, bb, _, _ = get("/stream.bin")
    results.append(st == 200 and bb == want)
ths = [threading.Thread(target=worker) for _ in range(16)]
for t in ths: t.start()
for t in ths: t.join()
chk("16 concurrent streams byte-exact", len(results) == 16 and all(results), f"{sum(results)}/16")

# ---- Range (RFC 7233) + conditional GET (RFC 7232) ----
fdata = open(ROOT+"/f.txt","rb").read(); N = len(fdata)
s,b,h = req_full("/f.txt")
chk("Accept-Ranges advertised", h.get("accept-ranges")=="bytes", str(h.get("accept-ranges")))
etag = h.get("etag"); lastmod = h.get("last-modified")
chk("ETag + Last-Modified present", bool(etag) and bool(lastmod), f"{etag} / {lastmod}")

s,b,h = req_full("/f.txt", {"Range":"bytes=0-99"})
chk("range 0-99 -> 206 partial", s==206 and b==fdata[0:100] and h.get("content-range")==f"bytes 0-99/{N}",
    f"status={s} cr={h.get('content-range')}")
s,b,h = req_full("/f.txt", {"Range":"bytes=-50"})
chk("suffix range -> last 50", s==206 and b==fdata[-50:], f"status={s} len={len(b)}")
s,b,h = req_full("/f.txt", {"Range":"bytes=100-"})
chk("open-ended range -> from 100", s==206 and b==fdata[100:], f"status={s} len={len(b)}")
s,b,h = req_full("/f.txt", {"Range":"bytes=999999-"})
chk("unsatisfiable -> 416", s==416 and h.get("content-range")==f"bytes */{N}", f"status={s}")

# range on the streamed (large) file path
sdata = open(ROOT+"/stream.bin","rb").read()
s,b,h = req_full("/stream.bin", {"Range":"bytes=500000-599999"})
chk("ranged streamed file byte-exact", s==206 and b==sdata[500000:600000], f"status={s} len={len(b)}")

# conditional GET
s,b,h = req_full("/f.txt", {"If-None-Match": etag})
chk("If-None-Match (current) -> 304", s==304 and b==b"", f"status={s} bodylen={len(b)}")
s,b,h = req_full("/f.txt", {"If-None-Match": '"stale"'})
chk("If-None-Match (stale) -> 200 full", s==200 and b==fdata, f"status={s}")
s,b,h = req_full("/f.txt", {"If-Modified-Since": "Wed, 01 Jan 2031 00:00:00 GMT"})
chk("If-Modified-Since future -> 304", s==304, f"status={s}")
s,b,h = req_full("/f.txt", {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"})
chk("If-Modified-Since past -> 200", s==200 and b==fdata, f"status={s}")

# If-Range: matching validator serves the range; stale one serves the full body
s,b,h = req_full("/f.txt", {"Range":"bytes=0-9", "If-Range": etag})
chk("If-Range match -> 206", s==206 and b==fdata[0:10], f"status={s}")
s,b,h = req_full("/f.txt", {"Range":"bytes=0-9", "If-Range": '"stale"'})
chk("If-Range mismatch -> 200 full", s==200 and b==fdata, f"status={s}")

# ---- directory index ----
s,b,_,_ = get("/sub/")
chk("directory -> index.html", s==200 and b==b"SUBDIR INDEX", f"status={s}")
s,b,_,_ = get("/sub")
chk("directory (no trailing slash) -> index", s==200 and b==b"SUBDIR INDEX", f"status={s}")
s,_,_,_ = get("/noindex/")
chk("directory without index -> 403", s==403, f"status={s}")

print(f"\n{'PASS' if fail==0 else 'FAIL'}  ({ok} ok, {fail} failed)")
sys.exit(1 if fail else 0)
PY
RC1=$?

# ---- URL-prefix stripping: a second server mounting the docroot at /static ----
kill "$SRV" 2>/dev/null; SRV=
PORT2=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
STATIC_ROOT="$ROOT" STATIC_PREFIX="/static" PORT="$PORT2" "$BIN" >/tmp/portico_static_srv2.log 2>&1 &
SRV=$!
for i in $(seq 1 80); do
  (exec 3<>/dev/tcp/127.0.0.1/"$PORT2") 2>/dev/null && { exec 3>&-; break; }
  sleep 0.1
done
code() { curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT2$1"; }
RC2=0
echo "== prefix mount (/static) =="
chkp() { if [ "$2" = "$3" ]; then echo "  ok    $1 ($2)"; else echo "  FAIL  $1: got $2 want $3"; RC2=1; fi; }
chkp "/static/f.txt served"        "$(code /static/f.txt)"     "200"
chkp "/static/sub/ -> dir index"   "$(code /static/sub/)"      "200"
chkp "/static/escape.txt symlink"  "$(code /static/escape.txt)" "403"
chkp "/static/../etc/passwd 403"   "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "http://127.0.0.1:$PORT2/static/../../../etc/passwd")" "403"
chkp "/f.txt outside mount -> 404" "$(code /f.txt)"            "404"
chkp "/staticfoo not a segment"    "$(code /staticfoo)"        "404"

[ "$RC1" = 0 ] && [ "$RC2" = 0 ] && echo "ALL PASS" || { echo "SOME FAILED"; exit 1; }
