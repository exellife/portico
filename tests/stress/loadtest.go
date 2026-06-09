// portico load tester — dependency-free (stdlib only), hand-rolled WS framing.
//
// Modes:
//   http     closed-loop keep-alive requests -> req/sec + latency percentiles
//   ws       WebSocket echo round-trips      -> msg/sec + latency percentiles
//   wsconns  open and hold N connections     -> connection-scaling / memory
//   fuzz     malformed frames at speed       -> stability/race shaking (no metrics)
//
// Usage:
//   go run loadtest.go -mode http -addr 127.0.0.1:8090 -conns 200 -dur 10s
//   go run loadtest.go -mode ws   -conns 200 -size 128 -dur 10s
//   go run loadtest.go -mode wsconns -conns 50000 -dur 30s -ramp 50us
//   go run loadtest.go -mode fuzz -conns 200 -dur 20s
//
// -addr accepts a comma-separated list of server addresses so large connection
// counts can be spread across multiple destination IPs (loopback aliases) to
// dodge the ~28k ephemeral-port-per-4-tuple ceiling.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"net/textproto"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ---- latency histogram (linear, 5us buckets to 200ms + exact max) -----------

const histStep = 5      // microseconds per bucket
const histBuckets = 40000 // 0..200ms; anything higher clamps to the last bucket

type hist struct {
	buckets []uint64
	count   uint64
	sum     uint64 // total microseconds (for mean)
	max     uint64
}

func newHist() *hist { return &hist{buckets: make([]uint64, histBuckets)} }

func (h *hist) record(us uint64) {
	h.count++
	h.sum += us
	if us > h.max {
		h.max = us
	}
	b := int(us / histStep)
	if b >= histBuckets {
		b = histBuckets - 1
	}
	h.buckets[b]++
}

func (h *hist) merge(o *hist) {
	h.count += o.count
	h.sum += o.sum
	if o.max > h.max {
		h.max = o.max
	}
	for i := range h.buckets {
		h.buckets[i] += o.buckets[i]
	}
}

func (h *hist) pct(p float64) uint64 {
	if h.count == 0 {
		return 0
	}
	target := uint64(math.Ceil(p / 100.0 * float64(h.count)))
	var cum uint64
	for i, c := range h.buckets {
		cum += c
		if cum >= target {
			return uint64(i) * histStep
		}
	}
	return h.max
}

func (h *hist) mean() float64 {
	if h.count == 0 {
		return 0
	}
	return float64(h.sum) / float64(h.count)
}

// ---- shared dialer ----------------------------------------------------------

func dial(addrs []string, i int) (net.Conn, error) {
	a := addrs[i%len(addrs)]
	c, err := net.DialTimeout("tcp", a, 5*time.Second)
	if err == nil {
		if t, ok := c.(*net.TCPConn); ok {
			t.SetNoDelay(true)
		}
	}
	return c, err
}

// ---- WebSocket framing (client side) ----------------------------------------

func wsHandshake(c net.Conn, br *bufio.Reader, host string) error {
	var k [16]byte
	rand.Read(k[:])
	key := base64.StdEncoding.EncodeToString(k[:])
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return err
	}
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}
	if len(line) < 12 || line[9:12] != "101" {
		return fmt.Errorf("handshake: %q", line)
	}
	_, err = tp.ReadMIMEHeader()
	return err
}

// write one masked client frame
func wsWrite(c net.Conn, opcode byte, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | opcode // FIN + opcode
	n := len(payload)
	var hl int
	switch {
	case n < 126:
		hdr[1] = 0x80 | byte(n)
		hl = 2
	case n < 65536:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
		hl = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
		hl = 10
	}
	var mask [4]byte
	binary.LittleEndian.PutUint32(mask[:], mrand.Uint32())
	copy(hdr[hl:hl+4], mask[:])
	hl += 4
	buf := make([]byte, hl+n)
	copy(buf, hdr[:hl])
	for i := 0; i < n; i++ {
		buf[hl+i] = payload[i] ^ mask[i&3]
	}
	_, err := c.Write(buf)
	return err
}

// read one server frame (unmasked), returning opcode + payload length consumed
func wsRead(br *bufio.Reader) (byte, []byte, error) {
	var h2 [2]byte
	if _, err := io.ReadFull(br, h2[:]); err != nil {
		return 0, nil, err
	}
	opcode := h2[0] & 0x0f
	masked := h2[1] & 0x80
	n := int(h2[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(br, e[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(br, e[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint64(e[:]))
	}
	if masked != 0 {
		var m [4]byte
		io.ReadFull(br, m[:])
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(br, p); err != nil {
		return 0, nil, err
	}
	return opcode, p, nil
}

// ---- metrics aggregation ----------------------------------------------------

type result struct {
	ops   uint64
	errs  uint64
	h     *hist
	extra string
}

func report(mode string, conns int, d time.Duration, total *result, extra string) {
	secs := d.Seconds()
	fmt.Printf("\n== %s: %d conns, %.1fs ==\n", mode, conns, secs)
	fmt.Printf("  ops:        %d  (%.0f/sec)\n", total.ops, float64(total.ops)/secs)
	fmt.Printf("  errors:     %d\n", total.errs)
	if total.h != nil && total.h.count > 0 {
		fmt.Printf("  latency us: mean=%.0f p50=%d p90=%d p99=%d p99.9=%d max=%d\n",
			total.h.mean(), total.h.pct(50), total.h.pct(90),
			total.h.pct(99), total.h.pct(99.9), total.h.max)
	}
	if extra != "" {
		fmt.Print(extra)
	}
}

// ---- HTTP closed-loop -------------------------------------------------------

func runHTTP(addrs []string, conns int, d time.Duration, path string, size int) *result {
	deadline := time.Now().Add(d)
	results := make([]*result, conns)
	var wg sync.WaitGroup
	host := addrs[0]
	var reqBytes []byte
	if size > 0 {
		body := make([]byte, size)
		reqBytes = []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", "/echo", host, size))
		reqBytes = append(reqBytes, body...)
	} else {
		reqBytes = []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host))
	}
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := &result{h: newHist()}
			results[id] = r
			var c net.Conn
			var br *bufio.Reader
			reconnect := func() bool {
				if c != nil {
					c.Close()
				}
				var err error
				c, err = dial(addrs, id)
				if err != nil {
					r.errs++
					return false
				}
				br = bufio.NewReaderSize(c, 8192)
				c.SetDeadline(deadline.Add(3 * time.Second)) // bound all I/O to the test window
				return true
			}
			if !reconnect() {
				return
			}
			tp := textproto.NewReader(br)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				if _, err := c.Write(reqBytes); err != nil {
					r.errs++
					if !reconnect() {
						return
					}
					tp = textproto.NewReader(br)
					continue
				}
				line, err := tp.ReadLine()
				if err != nil {
					r.errs++
					if !reconnect() {
						return
					}
					tp = textproto.NewReader(br)
					continue
				}
				hdr, err := tp.ReadMIMEHeader()
				if err != nil {
					r.errs++
					if !reconnect() {
						return
					}
					tp = textproto.NewReader(br)
					continue
				}
				cl := 0
				fmt.Sscanf(hdr.Get("Content-Length"), "%d", &cl)
				if cl > 0 {
					if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
						r.errs++
						if !reconnect() {
							return
						}
						tp = textproto.NewReader(br)
						continue
					}
				}
				_ = line
				r.h.record(uint64(time.Since(t0).Microseconds()))
				r.ops++
			}
			c.Close()
		}(i)
	}
	wg.Wait()
	return mergeResults(results)
}

// ---- WS echo round-trip -----------------------------------------------------

func runWS(addrs []string, conns int, d time.Duration, size int) *result {
	if size <= 0 {
		size = 64
	}
	deadline := time.Now().Add(d)
	results := make([]*result, conns)
	var wg sync.WaitGroup
	host := addrs[0]
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := &result{h: newHist()}
			results[id] = r
			c, err := dial(addrs, id)
			if err != nil {
				r.errs++
				return
			}
			defer c.Close()
			c.SetDeadline(deadline.Add(3 * time.Second)) // bound all I/O to the test window
			br := bufio.NewReaderSize(c, 8192)
			if err := wsHandshake(c, br, host); err != nil {
				r.errs++
				return
			}
			payload := make([]byte, size)
			mrand.Read(payload)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				if err := wsWrite(c, 0x2, payload); err != nil { // binary
					r.errs++
					return
				}
				if _, _, err := wsRead(br); err != nil {
					r.errs++
					return
				}
				r.h.record(uint64(time.Since(t0).Microseconds()))
				r.ops++
			}
		}(i)
	}
	wg.Wait()
	return mergeResults(results)
}

// ---- WS connection scaling --------------------------------------------------

func runWSConns(addrs []string, conns int, d time.Duration, rampStep time.Duration) *result {
	var established int64
	var failed int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(d)
	for i := 0; i < conns; i++ {
		if rampStep > 0 {
			time.Sleep(rampStep)
		}
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c, err := dial(addrs, id)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				return
			}
			defer c.Close()
			br := bufio.NewReaderSize(c, 1024)
			c.SetDeadline(time.Now().Add(10 * time.Second)) // bound the handshake
			if err := wsHandshake(c, br, addrs[0]); err != nil {
				atomic.AddInt64(&failed, 1)
				return
			}
			atomic.AddInt64(&established, 1)
			// hold the connection: send a ping every few seconds, drain anything.
			c.SetReadDeadline(time.Now().Add(time.Until(deadline) + 2*time.Second))
			for time.Now().Before(deadline) {
				time.Sleep(3 * time.Second)
				if time.Now().After(deadline) {
					break
				}
				if err := wsWrite(c, 0x9, nil); err != nil { // ping
					break
				}
			}
		}(i)
		if atomic.LoadInt64(&established)+atomic.LoadInt64(&failed) >= 0 {
			// periodic progress
			if i%5000 == 0 && i > 0 {
				fmt.Printf("  ramped %d/%d (established=%d failed=%d)\n",
					i, conns, atomic.LoadInt64(&established), atomic.LoadInt64(&failed))
			}
		}
	}
	// give late handshakes a moment, then snapshot
	time.Sleep(500 * time.Millisecond)
	est := atomic.LoadInt64(&established)
	fail := atomic.LoadInt64(&failed)
	extra := fmt.Sprintf("  established: %d\n  failed:      %d\n", est, fail)
	wg.Wait()
	return &result{ops: uint64(est), errs: uint64(fail), extra: extra}
}

// ---- fuzz: malformed frames under load --------------------------------------

func runFuzz(addrs []string, conns int, d time.Duration) *result {
	deadline := time.Now().Add(d)
	var ops, errs int64
	var wg sync.WaitGroup
	host := addrs[0]
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(id) * 2654435761))
			for time.Now().Before(deadline) {
				c, err := dial(addrs, id)
				if err != nil {
					atomic.AddInt64(&errs, 1)
					continue
				}
				c.SetDeadline(time.Now().Add(2 * time.Second)) // fuzz conns are short-lived; never block
				br := bufio.NewReaderSize(c, 1024)
				// half the time do a real handshake then send garbage frames;
				// half the time send garbage immediately (pre-handshake).
				if rng.Intn(2) == 0 {
					if wsHandshake(c, br, host) == nil {
						for j := 0; j < 20 && time.Now().Before(deadline); j++ {
							switch rng.Intn(6) {
							case 0: // oversized control frame
								wsWrite(c, 0x9, randBytes(rng, 200))
							case 1: // reserved opcode
								wsWrite(c, byte(3+rng.Intn(5)), randBytes(rng, rng.Intn(64)))
							case 2: // bad close code
								body := []byte{byte(rng.Intn(256)), byte(rng.Intn(256))}
								wsWrite(c, 0x8, body)
							case 3: // invalid utf8 text
								wsWrite(c, 0x1, []byte{0xff, 0xfe, 0xfd})
							case 4: // huge declared length, short body (raw)
								c.Write([]byte{0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4})
							default: // random raw bytes
								c.Write(randBytes(rng, rng.Intn(256)))
							}
						}
					}
				} else {
					c.Write(randBytes(rng, rng.Intn(512)))
				}
				c.Close()
				atomic.AddInt64(&ops, 1)
			}
		}(i)
	}
	wg.Wait()
	return &result{ops: uint64(ops), errs: uint64(errs)}
}

func randBytes(rng *mrand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}

// ---- helpers ----------------------------------------------------------------

func mergeResults(rs []*result) *result {
	out := &result{h: newHist()}
	for _, r := range rs {
		if r == nil {
			continue
		}
		out.ops += r.ops
		out.errs += r.errs
		if r.h != nil {
			out.h.merge(r.h)
		}
	}
	return out
}

func main() {
	mode := flag.String("mode", "http", "http|ws|wsconns|fuzz")
	addr := flag.String("addr", "127.0.0.1:8090", "comma-separated server addrs")
	conns := flag.Int("conns", 100, "concurrent connections")
	dur := flag.Duration("dur", 10*time.Second, "test duration")
	size := flag.Int("size", 0, "payload size (ws echo bytes / http POST bytes)")
	path := flag.String("path", "/health", "http GET path")
	ramp := flag.Duration("ramp", 0, "delay between connection starts (wsconns)")
	flag.Parse()

	addrs := splitComma(*addr)
	start := time.Now()
	var res *result
	var extra string
	switch *mode {
	case "http":
		res = runHTTP(addrs, *conns, *dur, *path, *size)
	case "ws":
		res = runWS(addrs, *conns, *dur, *size)
	case "wsconns":
		res = runWSConns(addrs, *conns, *dur, *ramp)
		extra = res.extra
	case "fuzz":
		res = runFuzz(addrs, *conns, *dur)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", *mode)
		os.Exit(2)
	}
	report(*mode, *conns, time.Since(start), res, extra)
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
