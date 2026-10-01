//! Dedicated upstream clients, one per distinct option set.
//!
//! The shared pool (`crate::pool`) speaks HTTP/1.1 over TCP, verifies TLS
//! against the public roots and connects within 5 s. A rule that needs
//! anything else — HTTP/2, its own CA, no verification, another SNI, a client
//! certificate, a Unix socket, another connect timeout — gets a client built
//! for exactly that, when the configuration loads. Clients are kept in a
//! registry keyed by the option set, so rules with the same options share one
//! client (and its connection pool), and a reload that leaves a rule's
//! options alone keeps its warm connections. The registry holds them weakly:
//! once no loaded configuration refers to a client, it goes, pool and all.

use super::unix::UnixConnector;
use super::UpstreamOptions;
use crate::pool::{ProxyClient, ProxyRequestBody, DEFAULT_CONNECT_TIMEOUT};
use anyhow::{Context, Result};
use hyper::Request;
use hyper_util::client::legacy::{Client, ResponseFuture};
use hyper_util::rt::TokioTimer;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;

/// Everything that makes one upstream client differ from another.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct ClientKey {
    h2: bool,
    connect_timeout_ms: Option<u64>,
    tls: TlsKey,
    /// Connect to this socket instead of the URI's host.
    unix: Option<PathBuf>,
}

/// The TLS side of a [`ClientKey`]. Files are part of the key with their
/// contents, so a reload after a CA or certificate was replaced on disk
/// builds a new client rather than reusing the one with the old trust.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct TlsKey {
    ca: Option<TlsFile>,
    insecure: bool,
    sni: Option<String>,
    client_cert: Option<(TlsFile, TlsFile)>,
}

/// A TLS file as read once, when the key is made: the client is built from
/// these very bytes. The digest and the trust store used to come from two
/// separate reads, so a file replaced in between gave a client whose trust
/// did not match its key — and the second read ran inside the registry lock.
#[derive(Clone, Debug)]
struct TlsFile {
    path: PathBuf,
    /// What the directive names it, for messages (`@tls_ca`, …).
    what: &'static str,
    bytes: Arc<[u8]>,
    digest: u64,
}

impl PartialEq for TlsFile {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.bytes == other.bytes
    }
}

impl Eq for TlsFile {}

impl Hash for TlsFile {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.digest.hash(state);
    }
}

/// Largest TLS file read. A CA bundle — the whole public root set included —
/// or a certificate chain is a few hundred KiB at most.
const MAX_TLS_FILE: u64 = 1024 * 1024;

impl TlsFile {
    /// Read `path` for the directive `what`.
    ///
    /// Only a regular file of at most [`MAX_TLS_FILE`] is read, and it is
    /// opened non-blocking, so a FIFO cannot hold the load (or the admin
    /// request that triggered it) forever, nor `/dev/zero` fill the memory.
    /// The read happens off the async workers when called on one.
    ///
    /// ⚠️ **The error says which file, never why.** It reaches the admin
    /// API's answers (`POST /api/v1/routes`, `POST /api/v1/config/validate`):
    /// "no such file" vs "permission denied" vs "not a certificate" — or a
    /// PEM parser quoting the line it choked on — would make the proxy a
    /// probe of its own filesystem. The reason goes to the log.
    fn read(path: &str, what: &'static str) -> Result<Self> {
        let bytes = off_the_workers(|| read_bounded(std::path::Path::new(path)))
            .map_err(|e| unusable(std::path::Path::new(path), what, e))?;
        let digest = {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut h);
            h.finish()
        };
        Ok(Self {
            path: PathBuf::from(path),
            what,
            bytes: bytes.into(),
            digest,
        })
    }

    /// The generic error for a file that cannot be used, with `detail` logged.
    fn unusable(&self, detail: impl std::fmt::Display) -> anyhow::Error {
        unusable(&self.path, self.what, detail)
    }
}

/// See [`TlsFile::read`]: `detail` is logged, the error names the file only.
fn unusable(path: &std::path::Path, what: &str, detail: impl std::fmt::Display) -> anyhow::Error {
    tracing::warn!("{} {}: {:#}", what, path.display(), detail);
    anyhow::anyhow!(
        "cannot load TLS file {} ({}); the proxy's log says why",
        path.display(),
        what
    )
}

/// Read a regular file of at most [`MAX_TLS_FILE`] bytes.
fn read_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind, Read};
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK: opening a FIFO for reading otherwise waits for a writer.
    // On a regular file it changes nothing.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::new(ErrorKind::InvalidInput, "not a regular file"));
    }
    if meta.len() > MAX_TLS_FILE {
        return Err(Error::new(ErrorKind::InvalidInput, "larger than 1 MiB"));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_TLS_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TLS_FILE {
        return Err(Error::new(ErrorKind::InvalidInput, "larger than 1 MiB"));
    }
    Ok(bytes)
}

/// Run blocking file I/O. A configuration is loaded from async code too — a
/// reload, an admin API write, `POST /api/v1/config/validate` — and a read
/// there would stall a tokio worker and every connection queued on it; on a
/// multi-threaded runtime the worker hands its tasks over first
/// (`block_in_place`). Elsewhere (startup, the CLI, tests on a
/// current-thread runtime) it simply runs.
fn off_the_workers<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

impl ClientKey {
    /// The key for a rule's TCP targets. Reads the TLS files the options
    /// name — here, once, and not under the registry lock.
    pub(crate) fn for_options(opts: &UpstreamOptions) -> Result<Self> {
        let ca = match &opts.tls_ca {
            Some(path) => Some(TlsFile::read(path, "@tls_ca")?),
            None => None,
        };
        let client_cert = match (&opts.tls_client_cert, &opts.tls_client_key) {
            (Some(cert), Some(key)) => Some((
                TlsFile::read(cert, "@tls_client_cert certificate")?,
                TlsFile::read(key, "@tls_client_cert key")?,
            )),
            _ => None,
        };
        Ok(Self {
            h2: opts.h2,
            connect_timeout_ms: opts.connect_timeout_ms,
            tls: TlsKey {
                ca,
                insecure: opts.tls_insecure,
                sni: opts.tls_sni.clone(),
                client_cert,
            },
            unix: None,
        })
    }

    /// Whether this is exactly what the shared pool already is.
    pub(crate) fn is_shared_default(&self) -> bool {
        *self == Self::default()
    }

    pub(crate) fn with_h2(&self) -> Self {
        Self {
            h2: true,
            ..self.clone()
        }
    }

    pub(crate) fn with_unix(&self, path: PathBuf) -> Self {
        Self {
            unix: Some(path),
            ..self.clone()
        }
    }

    fn connect_timeout(&self) -> Duration {
        self.connect_timeout_ms
            .map_or(DEFAULT_CONNECT_TIMEOUT, Duration::from_millis)
    }
}

/// A hyper client for one option set.
pub struct UpstreamClient {
    h2: bool,
    /// `@connect_timeout`, or the 5 s default.
    connect_timeout: Duration,
    inner: Inner,
    /// For a TCP client with TLS options of its own: its TLS settings (without
    /// ALPN) and SNI override, for the WebSocket tunnel, which does its own
    /// TLS handshake.
    websocket_tls: Option<(tokio_rustls::TlsConnector, Option<ServerName<'static>>)>,
}

enum Inner {
    Tcp(ProxyClient),
    Unix(Client<UnixConnector, ProxyRequestBody>),
}

impl UpstreamClient {
    /// Send `req`. The same future type as the shared pool's, so callers
    /// treat both alike.
    pub fn request(&self, req: Request<ProxyRequestBody>) -> ResponseFuture {
        match &self.inner {
            Inner::Tcp(c) => c.request(req),
            Inner::Unix(c) => c.request(req),
        }
    }

    /// Whether requests go out as HTTP/2 (`@h2`, `h2c://`).
    pub fn is_h2(&self) -> bool {
        self.h2
    }

    /// The connect timeout this client applies — for the WebSocket tunnel,
    /// which connects by itself.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Whether this client connects to a Unix socket.
    pub fn is_unix(&self) -> bool {
        matches!(self.inner, Inner::Unix(_))
    }

    /// The TLS connector a WebSocket upgrade to this client's targets should
    /// use, and the SNI to send instead of the target's host; `None` when the
    /// public roots and the target's own name apply.
    pub fn websocket_tls(
        &self,
    ) -> Option<(&tokio_rustls::TlsConnector, Option<&ServerName<'static>>)> {
        self.websocket_tls
            .as_ref()
            .map(|(c, sni)| (c, sni.as_ref()))
    }
}

static REGISTRY: LazyLock<parking_lot::Mutex<HashMap<ClientKey, Weak<UpstreamClient>>>> =
    LazyLock::new(Default::default);

/// The client for `key`: the one already serving that option set, or a new
/// one. Called while a configuration loads, never per request.
pub(crate) fn get_or_build(key: &ClientKey) -> Result<Arc<UpstreamClient>> {
    let mut registry = REGISTRY.lock();
    if let Some(client) = registry.get(key).and_then(Weak::upgrade) {
        return Ok(client);
    }
    let client = Arc::new(build(key)?);
    // Forget the option sets no configuration uses any more.
    registry.retain(|_, weak| weak.strong_count() > 0);
    registry.insert(key.clone(), Arc::downgrade(&client));
    Ok(client)
}

static DEFAULT_H2C: LazyLock<Arc<UpstreamClient>> = LazyLock::new(|| {
    get_or_build(&ClientKey::default().with_h2())
        .expect("a client without TLS files or a socket cannot fail to build")
});

/// HTTP/2 with prior knowledge and default options: for an `h2c://` URL a
/// Lua `on_route` hook substituted on a rule that has no client of its own.
pub(crate) fn default_h2c() -> &'static UpstreamClient {
    &DEFAULT_H2C
}

fn build(key: &ClientKey) -> Result<UpstreamClient> {
    let mut builder = crate::pool::client_builder();
    if key.h2 {
        builder
            .http2_only(true)
            // HTTP/2 PINGs need a timer; they find a dead upstream
            // connection before a request is lost on it.
            .timer(TokioTimer::new())
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_timeout(Duration::from_secs(10));
    }
    let mut websocket_tls = None;
    let inner = match &key.unix {
        Some(path) => {
            Inner::Unix(builder.build(UnixConnector::new(path.clone(), key.connect_timeout())))
        }
        None => {
            let tls = tls_config(&key.tls)?;
            let sni = match &key.tls.sni {
                Some(name) => Some(
                    ServerName::try_from(name.clone())
                        .with_context(|| format!("@tls_sni:{} is not a DNS name or IP", name))?,
                ),
                None => None,
            };
            if key.tls != TlsKey::default() {
                websocket_tls = Some((
                    tokio_rustls::TlsConnector::from(Arc::new(tls.clone())),
                    sni.clone(),
                ));
            }
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls)
                .https_or_http();
            let https = match sni {
                Some(name) => https
                    .with_server_name_resolver(hyper_rustls::FixedServerNameResolver::new(name)),
                None => https,
            };
            let tcp = crate::pool::tcp_connector(key.connect_timeout());
            // ALPN: `h2` alone for an HTTP/2 client, so a TLS upstream that
            // cannot speak it fails the handshake instead of being sent
            // HTTP/2 frames over an HTTP/1.1 connection.
            let connector = if key.h2 {
                https.enable_http2().wrap_connector(tcp)
            } else {
                https.enable_http1().wrap_connector(tcp)
            };
            Inner::Tcp(builder.build(connector))
        }
    };
    Ok(UpstreamClient {
        h2: key.h2,
        connect_timeout: key.connect_timeout(),
        inner,
        websocket_tls,
    })
}

/// The process's crypto provider: aws-lc-rs, named explicitly so a client can
/// be built before (or without) a process default being installed.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn tls_config(key: &TlsKey) -> Result<ClientConfig> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?;
    let builder = if key.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification(provider)))
    } else {
        let mut roots = RootCertStore::empty();
        match &key.ca {
            // A private CA replaces the public roots: the point of naming
            // one is to trust that PKI, not that PKI *and* every public CA.
            Some(ca) => {
                let mut n = 0;
                for cert in CertificateDer::pem_slice_iter(&ca.bytes) {
                    let cert = cert.map_err(|e| ca.unusable(format!("invalid PEM: {e}")))?;
                    roots
                        .add(cert)
                        .map_err(|e| ca.unusable(format!("invalid CA certificate: {e}")))?;
                    n += 1;
                }
                if n == 0 {
                    return Err(ca.unusable("holds no certificate"));
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        builder.with_root_certificates(roots)
    };
    Ok(match &key.client_cert {
        Some((cert, private_key)) => {
            let chain = CertificateDer::pem_slice_iter(&cert.bytes)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| cert.unusable(format!("invalid PEM: {e}")))?;
            if chain.is_empty() {
                return Err(cert.unusable("holds no certificate"));
            }
            let private = PrivateKeyDer::from_pem_slice(&private_key.bytes)
                .map_err(|e| private_key.unusable(format!("no usable private key: {e}")))?;
            builder
                .with_client_auth_cert(chain, private)
                .map_err(|e| cert.unusable(format!("certificate and key do not match: {e}")))?
        }
        None => builder.with_no_client_auth(),
    })
}

/// `@tls_insecure`: accept any certificate. The handshake signatures are
/// still checked — the peer must hold the key of the certificate it shows —
/// but nothing says that certificate is the upstream's.
#[derive(Debug)]
struct NoVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_key_is_the_shared_pool() {
        let opts = UpstreamOptions::default();
        assert!(ClientKey::for_options(&opts).unwrap().is_shared_default());
        let opts = UpstreamOptions {
            connect_timeout_ms: Some(2000),
            ..Default::default()
        };
        assert!(!ClientKey::for_options(&opts).unwrap().is_shared_default());
        let opts = UpstreamOptions {
            retries: Some(3),
            timeout_ms: Some(1000),
            ..Default::default()
        };
        assert!(
            ClientKey::for_options(&opts).unwrap().is_shared_default(),
            "retries and the request timeout need no client of their own"
        );
    }

    #[test]
    fn a_ca_file_is_keyed_by_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let ca = rcgen::generate_simple_self_signed(vec!["ca.test".into()]).unwrap();
        std::fs::write(&path, ca.serialize_pem().unwrap()).unwrap();
        let opts = UpstreamOptions {
            tls_ca: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let first = ClientKey::for_options(&opts).unwrap();
        let a = get_or_build(&first).unwrap();
        let b = get_or_build(&ClientKey::for_options(&opts).unwrap()).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "same file, same client");
        let other = rcgen::generate_simple_self_signed(vec!["ca2.test".into()]).unwrap();
        std::fs::write(&path, other.serialize_pem().unwrap()).unwrap();
        let second = ClientKey::for_options(&opts).unwrap();
        assert_ne!(first, second, "a replaced CA file is a new option set");
    }

    #[test]
    fn a_file_without_certificates_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pem");
        std::fs::write(&path, "not a certificate\n").unwrap();
        let opts = UpstreamOptions {
            tls_ca: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let key = ClientKey::for_options(&opts).unwrap();
        assert!(get_or_build(&key).is_err());
    }

    /// Every way a TLS file can be unusable gives the same answer, naming
    /// the file and nothing else: the admin API relays it, and "missing" vs
    /// "unreadable" vs "not a certificate" — or the PEM line the parser choked
    /// on — would make the proxy a probe of its own filesystem.
    #[test]
    fn unusable_tls_files_all_fail_alike_and_quote_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(
            &garbage,
            "-----BEGIN CERTIFICATE-----\nSECRET-LINE\n-----END NOPE-----\n",
        )
        .unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "SECRET-LINE\n").unwrap();
        let big = dir.path().join("big.pem");
        std::fs::write(&big, vec![b'a'; (MAX_TLS_FILE + 1) as usize]).unwrap();
        let fifo = dir.path().join("fifo.pem");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let missing = dir.path().join("missing.pem");

        for path in [
            &garbage,
            &empty,
            &big,
            &fifo,
            &missing,
            &dir.path().to_path_buf(),
        ] {
            let opts = UpstreamOptions {
                tls_ca: Some(path.to_string_lossy().into_owned()),
                ..Default::default()
            };
            // A FIFO with no writer must not block: this returns at once.
            let err = ClientKey::for_options(&opts)
                .and_then(|key| get_or_build(&key).map(|_| ()))
                .unwrap_err();
            assert_eq!(
                format!("{:#}", err),
                format!(
                    "cannot load TLS file {} (@tls_ca); the proxy's log says why",
                    path.display()
                )
            );
        }
    }

    /// The client is built from the bytes the key was made from: one read.
    #[test]
    fn the_key_carries_the_bytes_the_client_is_built_from() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let ca = rcgen::generate_simple_self_signed(vec!["ca.test".into()]).unwrap();
        std::fs::write(&path, ca.serialize_pem().unwrap()).unwrap();
        let opts = UpstreamOptions {
            tls_ca: Some(path.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let key = ClientKey::for_options(&opts).unwrap();
        // Replaced after the key was made: the build does not read it again.
        std::fs::write(&path, "not a certificate").unwrap();
        assert!(get_or_build(&key).is_ok());
    }

    #[test]
    fn insecure_sni_and_h2_clients_build() {
        let opts = UpstreamOptions {
            tls_insecure: true,
            tls_sni: Some("internal.example".into()),
            h2: true,
            ..Default::default()
        };
        let client = get_or_build(&ClientKey::for_options(&opts).unwrap()).unwrap();
        assert!(client.is_h2() && !client.is_unix());
    }
}
