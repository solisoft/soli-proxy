use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;

use crate::acme::{
    build_server_config, certified_key_from_pem, load_certificate, AcmeCertResolver,
};
use crate::config::TlsConfig;

pub struct TlsManager {
    server_config: Option<Arc<ServerConfig>>,
    resolver: Arc<AcmeCertResolver>,
    cache_dir: PathBuf,
}

impl TlsManager {
    pub fn new(tls_config: &TlsConfig) -> Result<Self> {
        let cache_dir = PathBuf::from(&tls_config.cache_dir);
        std::fs::create_dir_all(&cache_dir).ok();

        let resolver = Arc::new(AcmeCertResolver::new());

        Ok(Self {
            server_config: None,
            resolver,
            cache_dir,
        })
    }

    /// Load self-signed fallback cert. Always called to ensure TLS works.
    pub fn load_self_signed_fallback(&self) -> Result<()> {
        let cert_path = self.cache_dir.join("self-signed.cert.pem");
        let key_path = self.cache_dir.join("self-signed.key.pem");

        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read(&cert_path)?;
            let key_pem = std::fs::read(&key_path)?;
            let ck = certified_key_from_pem(&cert_pem, &key_pem)?;
            self.resolver.set_fallback(Arc::new(ck));
            tracing::info!("Loaded existing self-signed fallback certificate");
            return Ok(());
        }

        tracing::info!("Generating self-signed TLS certificate...");
        let (cert_pem, key_pem) = generate_self_signed_cert()?;

        std::fs::create_dir_all(&self.cache_dir)?;
        std::fs::write(&cert_path, &cert_pem).context("Failed to write self-signed certificate")?;
        std::fs::write(&key_path, &key_pem).context("Failed to write self-signed key")?;

        let ck = certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        self.resolver.set_fallback(Arc::new(ck));

        tracing::info!(
            "Generated self-signed certificate at {}",
            cert_path.display()
        );
        Ok(())
    }

    /// Load cached ACME certs from disk into the resolver.
    pub fn load_cached_certs(&self, domains: &[String]) -> Result<()> {
        for domain in domains {
            match load_certificate(&self.cache_dir, domain) {
                Ok(Some(ck)) => {
                    self.resolver.set_cert(domain, ck);
                    tracing::info!("Loaded cached certificate for {}", domain);
                }
                Ok(None) => {
                    tracing::debug!("No cached certificate for {}", domain);
                }
                Err(e) => {
                    tracing::warn!("Failed to load cached cert for {}: {}", domain, e);
                }
            }
        }
        Ok(())
    }

    /// Build the ServerConfig using the cert resolver. Call after loading certs.
    pub fn build(&mut self) -> Result<()> {
        let config = build_server_config(self.resolver.clone())?;
        self.server_config = Some(config);
        Ok(())
    }

    pub fn server_config(&self) -> Option<&Arc<ServerConfig>> {
        self.server_config.as_ref()
    }

    pub fn cert_resolver(&self) -> Arc<AcmeCertResolver> {
        self.resolver.clone()
    }

    pub fn cache_dir(&self) -> &PathBuf {
        &self.cache_dir
    }
}

fn generate_self_signed_cert() -> Result<(String, String)> {
    let mut params = CertificateParams::default();

    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress([127, 0, 0, 1].into()),
    ];

    let cert = Certificate::from_params(params).context("Failed to generate certificate")?;
    let cert_pem = cert
        .serialize_pem()
        .context("Failed to serialize certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem, key_pem))
}
