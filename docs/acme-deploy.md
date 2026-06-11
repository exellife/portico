# Deploying portico with built-in ACME (Let's Encrypt)

End-to-end runbook for issuing a real certificate on a public box (e.g. an Oracle
Cloud Ampere/ARM64 VM). The binary is already proven against the Pebble test CA
locally; this is deploy-and-confirm. **Do staging first, then flip to production** —
production rate limits are unforgiving (≈50 certs/week/domain), staging is generous.

The ACME path is opt-in: it engages only when `ACME_DOMAINS` is set. Without it,
portico runs exactly as before.

---

## 0. What you need

- A **domain** you control (e.g. `portico.example.net`).
- The VM's **public IPv4** address.
- The repo built on the VM (ARM64 builds clean — it's plain C + OpenSSL).

How issuance works here, so the steps make sense: portico's main listener serves
**HTTPS on :443**; a tiny sidecar responder serves **HTTP-01 challenges on :80**. The
CA connects to `http://<domain>/.well-known/acme-challenge/<token>` on **:80**, so
:80 must be publicly reachable. Both are privileged ports (<1024).

---

## 1. Open the ports — BOTH layers (the Oracle gotcha)

Oracle has two independent firewalls. Miss either and the challenge times out.

**a) VCN Security List / NSG (cloud):** in the Console → your VCN → Subnet → Security
List → add **stateful ingress** rules, source `0.0.0.0/0`, IP protocol TCP, dest
ports **80** and **443**.

**b) Host firewall (the one everyone forgets):** Oracle's Ubuntu images ship iptables
rules that drop everything but SSH.

```bash
# Ubuntu / Debian images:
sudo iptables -I INPUT -p tcp --dport 80  -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo apt-get install -y netfilter-persistent iptables-persistent
sudo netfilter-persistent save

# Oracle Linux images (firewalld) instead:
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --reload
```

> **IPv6:** for the first run, publish an **A record only**. portico's responder is
> dual-stack, but if you publish an **AAAA** the CA may validate over IPv6 — and then
> the VM's IPv6 routing *and* the v6 firewall must also be open. Keep it IPv4-only
> until that's working, then add AAAA.

---

## 2. Point DNS at the VM

Create an **A** record: `portico.example.net → <public IPv4>`. Verify from elsewhere
(not the VM) that it resolves to the right IP before issuing:

```bash
dig +short portico.example.net      # must print the VM's public IP
```

DNS must be correct *before* you ask the CA to validate — it resolves your domain to
find :80.

---

## 3. Build on the VM

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev git
git clone <your portico remote> portico && cd portico
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
# binary: build/http_server
```

---

## 4. Let the binary bind :80 and :443 without root

Pick one:

```bash
# Preferred — grant the capability, run as a normal user:
sudo setcap cap_net_bind_service=+ep build/http_server

# Or just run the whole thing under sudo (fine for a first test).
```

Pick a **persistent, writable** directory for the account key + issued cert/key
(they're written 0600/0644):

```bash
sudo mkdir -p /var/lib/portico && sudo chown "$USER" /var/lib/portico
```

---

## 5. Issue against STAGING first

```bash
PORT=443 \
ACME_DOMAINS=portico.example.net \
ACME_EMAIL=you@a-real-domain.com \
ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory \
ACME_CHALLENGE_PORT=80 \
ACME_ACCOUNT_KEY=/var/lib/portico/account.key \
ACME_CERT=/var/lib/portico/cert.pem \
ACME_CERT_KEY=/var/lib/portico/cert.key \
  ./build/http_server
```

(`ACME_DIRECTORY` **defaults to staging**, so it's safe by default — but set it
explicitly so the flip to prod in §7 is just a one-line change.)

Use a **real** email — LE rejects `example.com`. Multiple names:
`ACME_DOMAINS=a.example.net,www.a.example.net` (each gets its own authorization).

**Expected log** — initial issuance is synchronous and blocks startup, so success or
failure is immediate:

```
acme: obtaining a certificate for 'portico.example.net' via https://acme-staging-v02...
acme: certificate ready (/var/lib/portico/cert.pem); HTTP-01 challenges on :80
portico http+ws server on :443
```

If it prints `acme: initial issuance failed`, see Troubleshooting.

**Verify the staging cert** (its issuer is the *untrusted* staging root, so use `-k`
/ read the issuer rather than expecting a trusted chain):

```bash
echo | openssl s_client -connect portico.example.net:443 \
       -servername portico.example.net 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
# issuer should say "(STAGING) Let's Encrypt" / "Fake LE"; subject CN = your domain
curl -kI https://portico.example.net/        # 200/404 over TLS = the cert is being served
```

---

## 6. Confirm the moving parts (if anything's off)

- `:80` reachable from outside? While the server runs, from your laptop:
  ```bash
  curl -I http://portico.example.net/.well-known/acme-challenge/probe   # 404 from portico = reachable
  ```
  A timeout/refused here means §1 (one of the two firewalls) or §2 (DNS).

---

## 7. Flip to PRODUCTION

Only after a clean staging run. The staging cert is untrusted, so you must re-issue
from prod into a **fresh** cert file:

```bash
# stop the staging server (Ctrl-C), then:
rm -f /var/lib/portico/cert.pem /var/lib/portico/cert.key   # force a fresh prod issue
# (the account.key may stay; it just registers a prod account on first prod use)

PORT=443 \
ACME_DOMAINS=portico.example.net \
ACME_EMAIL=you@a-real-domain.com \
ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory \
ACME_CHALLENGE_PORT=80 \
ACME_ACCOUNT_KEY=/var/lib/portico/account.key \
ACME_CERT=/var/lib/portico/cert.pem \
ACME_CERT_KEY=/var/lib/portico/cert.key \
  ./build/http_server
```

**Verify the real cert** — now it should be trusted with no `-k`:

```bash
curl -I https://portico.example.net/                         # works, trusted chain
echo | openssl s_client -connect portico.example.net:443 \
       -servername portico.example.net 2>/dev/null \
  | openssl x509 -noout -issuer                               # issuer "Let's Encrypt"
```

A browser padlock with no warning = done.

---

## 8. Run it as a service (auto-renew, survives reboot)

The manager renews automatically (checks every 12h, renews within 30 days of expiry)
and hot-reloads the cert with zero downtime — no cron needed. Make it a service so it
keeps running. `AmbientCapabilities` grants :80/:443 without root:

```ini
# /etc/systemd/system/portico.service
[Unit]
Description=portico (HTTPS + built-in ACME)
After=network-online.target
Wants=network-online.target

[Service]
User=portico
WorkingDirectory=/var/lib/portico
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
Environment=PORT=443
Environment=ACME_DOMAINS=portico.example.net
Environment=ACME_EMAIL=you@a-real-domain.com
Environment=ACME_DIRECTORY=https://acme-v02.api.letsencrypt.org/directory
Environment=ACME_CHALLENGE_PORT=80
Environment=ACME_ACCOUNT_KEY=/var/lib/portico/account.key
Environment=ACME_CERT=/var/lib/portico/cert.pem
Environment=ACME_CERT_KEY=/var/lib/portico/cert.key
ExecStart=/usr/local/bin/http_server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin portico 2>/dev/null || true
sudo install -o portico -g portico -d /var/lib/portico
sudo cp build/http_server /usr/local/bin/http_server
sudo systemctl daemon-reload && sudo systemctl enable --now portico
journalctl -u portico -f          # watch issuance + renewals
```

---

## 9. Troubleshooting

| Symptom (in the log / from the CA) | Cause | Fix |
|---|---|---|
| `connection` error, `Timeout`/`connection refused` on the challenge URL | :80 not reachable | §1 — VCN security list **and** host iptables; confirm with the §6 curl |
| `dial tcp [IPv6]:80 ... refused` | AAAA published but v6 not reachable | drop the AAAA for now (§1 note) |
| `rejectedIdentifier` / "forbidden by policy" | bad/again-reserved domain | use a domain you control; not `*.example.com` |
| `invalidContact` "forbidden domain" | `ACME_EMAIL` on a junk domain | use a real address |
| `initial issuance failed`, no CA log | DNS wrong | §2 — `dig` must return the VM IP |
| `429` / rate limited | too many prod issues | wait, and debug on **staging** |
| cert served but browser warns | you're still on staging | §7 — re-issue from prod into a fresh cert file |

Renewals: nothing to do — the background thread reissues and hot-reloads. To force a
test renewal, stop the service, `rm` the cert, start it again.
