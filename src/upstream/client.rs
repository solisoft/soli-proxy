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

/// The TLS side of a [`ClientKey`]. Files are part of the key with a digest
/// of their contents, so a reload after a CA or certificate was replaced on
/// disk builds a new client rather than reusing the one with the old trust.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct TlsKey {
    ca: Option<(PathBuf, u64)>,
    insecure: bool,
    sni: Option<String>,
    client_cert: Option<(PathBuf, PathBuf, u64)>,
}

fn digest(bytes: &[&[u8]]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    for b in bytes {
        b.hash(&mut h);
    }
    h.finish()
}

fn read(path: &str, what: &str) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {} {}", what, path))
}

impl ClientKey {
    /// The key for a rule's TCP targets.
    pub(crate) fn for_options(opts: &UpstreamOptions) -> Result<Self> {
        let ca = match &opts.tls_ca {
            Some(path) => {
                let pem = read(path, "@tls_ca")?;
                Some((PathBuf::from(path), digest(&[&pem])))
            }
            None => None,
        };
        let client_cert = match (&opts.tls_client_cert, &opts.tls_client_key) {
            (Some(cert), Some(key)) => {
                let c = read(cert, "@tls_client_cert certificate")?;
                let k = read(key, "@tls_client_cert key")?;
                Some((PathBuf::from(cert), PathBuf::from(key), digest(&[&c, &k])))
            }
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
            Some((path, _)) => {
                let pem = read(&path.to_string_lossy(), "@tls_ca")?;
                let mut n = 0;
                for cert in CertificateDer::pem_slice_iter(&pem) {
                    let cert =
                        cert.with_context(|| format!("invalid PEM in {}", path.display()))?;
                    roots
                        .add(cert)
                        .with_context(|| format!("invalid CA certificate in {}", path.display()))?;
                    n += 1;
                }
                if n == 0 {
                    anyhow::bail!("{} holds no certificate", path.display());
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        builder.with_root_certificates(roots)
    };
    Ok(match &key.client_cert {
        Some((cert, key_path, _)) => {
            let pem = read(&cert.to_string_lossy(), "@tls_client_cert certificate")?;
            let chain = CertificateDer::pem_slice_iter(&pem)
                .collect::<std::result::Result<Vec<_>, _>>()
                .with_context(|| format!("invalid PEM in {}", cert.display()))?;
            if chain.is_empty() {
                anyhow::bail!("{} holds no certificate", cert.display());
            }
            let key_pem = read(&key_path.to_string_lossy(), "@tls_client_cert key")?;
            let private = PrivateKeyDer::from_pem_slice(&key_pem)
                .with_context(|| format!("no usable private key in {}", key_path.display()))?;
            builder
                .with_client_auth_cert(chain, private)
                .context("client certificate and key do not match")?
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
