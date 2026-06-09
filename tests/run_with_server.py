#!/usr/bin/env python3
"""Boot a portico example server on a free port, run a test script, tear down.

Usage: run_with_server.py <server_binary> <test_script.py>
Runs: python3 <test_script> ws://127.0.0.1:<port>/   and forwards its exit code.
"""
import os, sys, socket, subprocess, time, tempfile

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p

def wait_listen(port, proc, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        with socket.socket() as s:
            s.settimeout(0.25)
            try:
                s.connect(("127.0.0.1", port)); return True
            except OSError:
                time.sleep(0.05)
    return False

def main():
    if len(sys.argv) < 3:
        print("usage: run_with_server.py <binary> <test_script>", file=sys.stderr); return 2
    binary, script = sys.argv[1], sys.argv[2]
    port = free_port()
    env = dict(os.environ, PORT=str(port))

    log = tempfile.NamedTemporaryFile(prefix="portico-", suffix=".log", delete=False)
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_listen(port, proc):
            print(f"server failed to listen on :{port}", file=sys.stderr)
            log.flush(); sys.stderr.write(open(log.name).read()); return 1
        rc = subprocess.call([sys.executable, script, f"ws://127.0.0.1:{port}/"], env=env)
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()
        log.flush()
    if rc != 0:
        sys.stderr.write("\n----- server log -----\n"); sys.stderr.write(open(log.name).read())
    os.unlink(log.name)
    return rc

if __name__ == "__main__":
    sys.exit(main())
