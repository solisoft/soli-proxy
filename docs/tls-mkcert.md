# Dev TLS with mkcert

For local development you usually want browser- and curl-trusted certs for
`*.test` aliases without paying the ACME tax. [mkcert](https://github.com/FiloSottile/mkcert)
gives you that: it generates a development root CA, installs it into the
system trust store, and signs leaf certs from it.

This doc covers wiring mkcert into the soli proxy, the gotcha that bit us in
practice, and the tooling shipped in `scripts/` to recover from it. It assumes
the multi-machine layout: the CA lives on a laptop, the certs are copied to a
separate proxy host.

> Running the proxy and the browser on one Arch/Omarchy workstation? See
> [`omarchy-dev-setup.md`](omarchy-dev-setup.md) instead — it covers the
> wildcard `.test` DNS and the privileged-port capability as well, plus the
> Linux-only trust-store gotcha (`mkcert -install` does not reach
> Chrome/Brave without `~/.pki/nssdb`).

## How the proxy uses cert files

The proxy loads everything in `tls.cache_dir` (default `./certs/`) **once at
startup**. On a TLS handshake it picks a cert in this order:

1. Exact match: `certs/<sni>.cert.pem`
2. Wildcard, one label deep: `certs/_wildcard.<parent>.cert.pem`
   (so `crm.solisoft.test` matches `_wildcard.solisoft.test.*`,
   but `a.b.solisoft.test` does **not**)
3. Self-signed fallback: `certs/self-signed.cert.pem`

> **Cert files are not hot-reloaded.** Neither `SIGUSR1` nor `POST
> /api/v1/reload` re-scan `certs/`. After dropping in or replacing a cert
> file you must fully restart the proxy.

See `README.md` § *TLS Certificates* for the file naming rules.

## First-time setup

On every machine that needs to trust the dev certs (your laptop, any client
that hits the proxy):

```bash
brew install mkcert nss           # macOS; nss is needed for Firefox trust
omarchy pkg add mkcert nss        # Arch/Omarchy; nss provides certutil
mkcert -install
```

On Linux, `mkcert -install` reaches the system store but **not** Chrome/Brave —
see [`omarchy-dev-setup.md`](omarchy-dev-setup.md#the-linux-gotcha-two-trust-stores-and-mkcert-only-fills-one).

Then on the machine where you keep the cert files (typically the laptop —
keep them where the trusted CA lives), generate one wildcard per parent
domain:

```bash
cd /tmp/certs
mkcert -cert-file _wildcard.solisoft.test.cert.pem \
       -key-file  _wildcard.solisoft.test.key.pem \
       "*.solisoft.test" "solisoft.test"
```

Copy both files into the proxy host's `certs/` dir, then restart the
proxy. On startup you should see:

```
Loaded wildcard certificate for *.solisoft.test
```

Verify from a client:

```bash
curl --cacert "$(mkcert -CAROOT)/rootCA.pem" \
     --resolve soli.solisoft.test:443:<proxy-ip> \
     https://soli.solisoft.test/
```

## The CA-rotation pitfall

mkcert's root CA is regenerated whenever you run `mkcert -uninstall &&
mkcert -install`, or after a clean OS reinstall. The new CA has the **same
subject DN** as the old one — both are `O=mkcert development CA, CN=mkcert
<user>@<host>` — but a **different key pair**.

Result: leaf certs signed by the *old* CA still display the right issuer
name, but no longer verify against the *current* `mkcert -CAROOT`. The
TLS handshake produces:

```
LibreSSL/3.3.6: error:04FFF068:rsa routines:CRYPTO_internal:bad signature
```

or with `openssl verify`:

```
error 7 at 0 depth lookup: certificate signature failure
```

This is what to look for: identical issuer string on both sides, but
`openssl verify` fails. The cure is to regenerate the leaf cert against
the current CA.

## Diagnosing — `scripts/diag-mkcert-mac.sh`

Run on the client machine. It:

1. Reports the cert the proxy is currently serving for an SNI (fingerprint
   + issuer).
2. Prints `mkcert -CAROOT` and the rootCA's fingerprint + subject.
3. Pulls the live cert and runs `openssl verify` against the local CA.

Section 4 is decisive:

* **`OK`** — client is fine; if curl still fails it's a `--cacert` typo or
  a system-trust override.
* **`certificate signature failure`** — CA mismatch. Use the regen script
  below.

## Fixing — `scripts/regen-mkcert-and-deploy.sh`

Run on the machine that has the trusted mkcert CA. It regenerates all three
known wildcards (`solisoft.test`, `delupay.test`, `letelegraphe.test`),
scps them to the proxy host's `certs/` dir, and restarts the proxy.

```bash
bash scripts/regen-mkcert-and-deploy.sh
```

Defaults are baked in for the current setup; override with env vars if
they change:

| Var          | Default                                                            |
| ------------ | ------------------------------------------------------------------ |
| `PROXY_SSH`  | `olivier.bonnaure@delupay.com@192.168.1.30`                        |
| `PROXY_DIR`  | `/home/olivier.bonnaure@delupay.com/workspace/soli/proxy`          |
| `PROXY_HOST` | `192.168.1.30` (used only by the post-deploy `openssl s_client`)   |

The script ends with `openssl verify` against the local CA — `OK` means
clients are good to go.

To add a new parent domain, edit the `PARENTS=(...)` array at the top of
the script.

## Why a full restart, not a reload

`AcmeCertResolver` is built from a one-shot scan of `certs/` in
`main.rs::main`. Hot-reload paths (config file watcher, `SIGUSR1`, admin
`POST /api/v1/reload`) only re-parse `config.toml` and rebuild routing —
they do not call `TlsManager::load_all_cached_certs` again. Until that
gap is closed, treat cert changes as a restart-required operation.

If you need a smoother reload story, the work is small: invoke
`load_all_cached_certs` + `build()` from the reload path and swap the
`Arc<ServerConfig>` atomically. File an issue or PR if it starts to bite.
