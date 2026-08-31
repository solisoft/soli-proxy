# Local dev setup on Omarchy / Arch Linux

Serving `*.test` hostnames from the proxy on a single Omarchy workstation takes
three independent pieces: wildcard DNS, permission to bind ports 80/443, and a
CA the browser trusts. Each fails with its own browser error, and the error
tells you which layer to look at:

| Browser error | Layer at fault | Section |
| --- | --- | --- |
| `ERR_NAME_NOT_RESOLVED` | DNS — nothing maps `*.test` to this machine | [1](#1-point-every-test-name-at-this-machine) |
| `ERR_CONNECTION_REFUSED` | The proxy is not bound to 80/443 | [2](#2-let-the-proxy-bind-80-and-443-as-a-normal-user) |
| `ERR_CERT_AUTHORITY_INVALID` | The browser does not trust the dev CA | [3](#3-browser-trusted-certs-with-mkcert) |

[`tls-mkcert.md`](tls-mkcert.md) covers the multi-machine case — a macOS laptop
holding the CA, certs copied to a remote proxy host. This doc is the
everything-on-one-box version.

Packages, all in the official repos:

```bash
omarchy pkg add dnsmasq mkcert nss
```

`nss` is not optional: it provides `certutil`, without which section 3 cannot
reach the browser's trust store.

## 1. Point every `*.test` name at this machine

`.test` is reserved for exactly this by [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761),
so it will never collide with a real domain. `/etc/hosts` cannot help — it has
no wildcard syntax — so the job needs a resolver.

Omarchy uses `systemd-resolved`, which has no wildcard-domain feature of its
own but does support **split DNS**: routing one domain to a different server.
So run `dnsmasq` as an authority for `.test` alone and point resolved at it.
Nothing about the existing upstream (`omarchy dns`, DNS-over-TLS) changes.

**`/etc/dnsmasq.conf`** — loopback only, on a private port so resolved keeps 53:

```ini
listen-address=127.0.0.1
port=5353
bind-interfaces

# Answer "test" and every *.test name with this machine.
address=/test/127.0.0.1

# Authoritative for .test and nothing else: never forward, and never read
# /etc/resolv.conf (that would point straight back at systemd-resolved).
no-resolv
no-hosts
```

Prefer `127.0.0.1` over the machine's LAN address: it survives DHCP changes and
works with the network down.

**`/etc/systemd/system/dns-test-domain.service`** — the split-DNS route.
`systemd-resolved` only accepts per-*link* routing domains, so the route needs
an interface to live on; a dummy one costs nothing:

```ini
[Unit]
Description=Route *.test DNS queries to the local dnsmasq instance
Requires=dnsmasq.service
After=dnsmasq.service systemd-resolved.service NetworkManager.service
PartOf=systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/bin/ip link del dnstest
ExecStart=/usr/bin/ip link add dnstest type dummy
ExecStart=/usr/bin/ip link set dnstest up
ExecStart=/usr/bin/ip addr add 192.0.2.53/32 dev dnstest
ExecStart=/bin/bash -c 'for i in $(seq 20); do /usr/bin/resolvectl dns dnstest 127.0.0.1:5353 && exit 0; sleep 0.25; done; exit 1'
ExecStart=/usr/bin/resolvectl domain dnstest '~test'
ExecStart=/usr/bin/resolvectl dnsovertls dnstest no
ExecStart=/usr/bin/resolvectl dnssec dnstest no
ExecStart=/usr/bin/resolvectl flush-caches
ExecStop=-/usr/bin/ip link del dnstest

[Install]
WantedBy=multi-user.target
```

**`/etc/NetworkManager/conf.d/30-dns-test-unmanaged.conf`** — NetworkManager
would otherwise adopt the dummy device and push its own DNS config onto the
link, silently undoing the route:

```ini
[keyfile]
unmanaged-devices=interface-name:dnstest
```

Keep this in its own file. `omarchy dns` rewrites `20-omarchy-dns.conf`
whenever the DNS provider changes, and would take these lines with it.

```bash
sudo systemctl daemon-reload
sudo systemctl reload NetworkManager
sudo systemctl enable --now dnsmasq dns-test-domain
```

### Two things that will waste an afternoon

**A dummy interface with no IP address gets no DNS scope.** `resolvectl` will
accept the configuration and display it back to you, while resolving nothing —
`systemd-resolved` does not activate a link's scope until the link has an
address of that family. The tell is `Current Scopes: none`:

```console
$ resolvectl status dnstest
Link 4 (dnstest)
    Current Scopes: none          # <- broken, needs an address
       DNS Servers: 127.0.0.1:5353
        DNS Domain: ~test
```

Healthy is `Current Scopes: DNS`. Hence the `192.0.2.53/32` above — TEST-NET-1
from [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737), reserved for
documentation and therefore guaranteed never to collide with a real route.

**`systemd-resolved` forgets per-link config when it restarts.** A routine
`systemctl restart systemd-resolved` — or a package upgrade — drops the route
and `.test` goes dark. `PartOf=systemd-resolved.service` re-applies it.

### Verifying

```bash
resolvectl status dnstest      # expect: Current Scopes: DNS
getent hosts anything.test     # expect: 127.0.0.1
```

Use `getent`, not `dig`: `getent` goes through NSS exactly like an application
does, while `dig` talks to a nameserver directly and can pass while every real
program still fails.

## 2. Let the proxy bind 80 and 443 as a normal user

Linux reserves ports below 1024. The proxy runs as your user, so it binds its
admin port fine and fails on the two ports it exists to serve:

```
INFO  Proxy server starting on 0.0.0.0:80
ERROR HTTP/1.1 server error (listener 3): Permission denied (os error 13)
ERROR HTTPS/2 server error (listener 0): Permission denied (os error 13)
```

Grant the capability to the binary:

```bash
sudo setcap cap_net_bind_service=+ep "$(command -v soli-proxy)"
```

Two consequences worth internalising:

- **Capabilities are read at `exec` time.** Setting them does nothing to the
  running process — restart the proxy.
- **Capabilities live on the file, not the path.** `cp`, `install`, `mv` across
  filesystems, and unpacking a release archive all drop them silently, so this
  recurs after *every* upgrade unless `setcap` is part of the upgrade. This is
  why `install.sh` output is worth re-reading after a version bump.

## 3. Browser-trusted certs with mkcert

Generate one wildcard per parent domain and drop it in `certs/`:

```bash
mkcert -install
cd certs
mkcert -cert-file _wildcard.solisoft.test.cert.pem \
       -key-file  _wildcard.solisoft.test.key.pem \
       "*.solisoft.test" "solisoft.test"
```

Restart the proxy — cert files are scanned once at startup and are **not**
hot-reloaded; see [`tls-mkcert.md`](tls-mkcert.md#why-a-full-restart-not-a-reload).

### The Linux gotcha: two trust stores, and mkcert only fills one

`mkcert -install` installs the root CA into the system store
(`/etc/ca-certificates/trust-source/anchors/`). **Chrome-family browsers on
Linux do not read that store for locally-added roots.** They read a per-user
NSS database at `~/.pki/nssdb`. On a fresh Omarchy install that directory does
not exist, so `mkcert -install` has nothing to install into and skips it
without printing a warning.

The result is a server that is provably correct and a browser that refuses it:

```console
$ curl -so /dev/null -w '%{http_code}\n' https://soli.solisoft.test/
200
```

while Brave shows `ERR_CERT_AUTHORITY_INVALID`.

**That contrast is the diagnosis.** If `curl` succeeds, the cert, the chain and
the proxy are all fine by definition — stop inspecting `certs/` and go look at
the browser's store. (If `curl` *also* fails, you have a genuine CA mismatch
instead; that is the rotation pitfall in
[`tls-mkcert.md`](tls-mkcert.md#the-ca-rotation-pitfall).)

Fix, entirely at user level — no `sudo`:

```bash
mkdir -p ~/.pki/nssdb
certutil -d sql:$HOME/.pki/nssdb -N --empty-password
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "mkcert development CA" \
  -i "$(mkcert -CAROOT)/rootCA.pem"
```

Confirm the CA is present and trusted for TLS — the `C` in the SSL column is
what matters:

```console
$ certutil -d sql:$HOME/.pki/nssdb -L
Certificate Nickname                       Trust Attributes
                                           SSL,S/MIME,JAR/XPI

mkcert development CA                      C,,
```

Then **fully quit and reopen the browser**. NSS is read at startup; a reload,
a new tab, or a new window will not pick up the change.

Firefox keeps yet another store, per profile under `~/.mozilla/firefox/*/`.
Re-running `mkcert -install` handles it once a profile exists.

## Checking the whole path

```bash
getent hosts soli.solisoft.test   # 1. DNS      -> 127.0.0.1
ss -lntp | grep -E ':(80|443)\s'  # 2. binding  -> proxy is listening
curl -sI https://soli.solisoft.test/ | head -1   # 3. TLS -> HTTP/2 200
```

Three green lines and a restarted browser means the page loads.
