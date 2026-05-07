use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;

use crate::acme::{
    build_server_config, certified_key_from_pem, load_certificate, AcmeCertResolver,
};
use crate::config::TlsConfig;

#[derive(Clone)]
pub struct TlsManager {
    server_config: Option<Arc<ServerConfig>>,
    resolver: Arc<AcmeCertResolver>,
    cache_dir: PathBuf,
}

impl TlsManager {
    pub fn new(tls_config: &TlsConfig) -> Result<Self> {
        let cache_dir = PathBuf::from(&tls_config.cache_dir);
        std::fs::create_dir_all(&cache_dir).ok();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&cache_dir) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(&cache_dir, perms).ok();
            }
        }

        let resolver = Arc::new(AcmeCertResolver::new());

        Ok(Self {
            server_config: None,
            resolver,
            cache_dir,
        })
    }

    /// Load self-signed fallback cert. Always called to ensure TLS works.
    pub fn load_self_signed_fallback(&self) -> Result<()> {
        self.load_self_signed_fallback_with_extra_sans(&[])
    }

    /// Load self-signed fallback cert with additional SANs for dev mode.
    pub fn load_self_signed_fallback_with_extra_sans(&self, extra_sans: &[String]) -> Result<()> {
        let cert_path = self.cache_dir.join("self-signed.cert.pem");
        let key_path = self.cache_dir.join("self-signed.key.pem");

        if cert_path.exists() && key_path.exists() && extra_sans.is_empty() {
            let cert_pem = std::fs::read(&cert_path)?;
            let key_pem = std::fs::read(&key_path)?;
            let ck = certified_key_from_pem(&cert_pem, &key_pem)?;
            self.resolver.set_fallback(Arc::new(ck));
            tracing::info!("Loaded existing self-signed fallback certificate");
            return Ok(());
        }

        tracing::info!("Generating self-signed TLS certificate...");
        let (cert_pem, key_pem) = generate_self_signed_cert(extra_sans)?;

        std::fs::create_dir_all(&self.cache_dir)?;

        let mut key_file = tempfile::NamedTempFile::new_in(&self.cache_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
                .context("Failed to set restrictive permissions on private key")?;
        }
        key_file.as_file_mut().write_all(key_pem.as_bytes())?;
        // Use `persist` (not `persist_noclobber`) so regeneration can replace
        // the prior key. The temp file lives in `cache_dir`, so the underlying
        // rename is atomic on the same filesystem.
        key_file
            .persist(&key_path)
            .context("Failed to persist private key")?;

        std::fs::write(&cert_path, &cert_pem).context("Failed to write self-signed certificate")?;

        let ck = certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        self.resolver.set_fallback(Arc::new(ck));

        tracing::info!(
            "Generated self-signed certificate at {}",
            cert_path.display()
        );
        Ok(())
    }

    /// Regenerate fallback certificate with additional SANs (for dev mode .test domains).
    pub fn regenerate_fallback_with_sans(&self, extra_sans: &[String]) -> Result<()> {
        tracing::info!("Regenerating self-signed fallback certificate with extra SANs...");
        self.load_self_signed_fallback_with_extra_sans(extra_sans)
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

    /// Load ALL cached ACME certs from disk by scanning the certs directory.
    /// This ensures certs for app domains are loaded even if not in proxy.conf.
    pub fn load_all_cached_certs(&self) -> Result<()> {
        let cert_dir = &self.cache_dir;
        if !cert_dir.exists() {
            return Ok(());
        }
        for dir_entry in std::fs::read_dir(cert_dir)? {
            let entry = dir_entry?;
            let filename = entry.file_name();
            let name = filename.to_str().unwrap_or("");
            if let Some(domain) = name.strip_suffix(".cert.pem") {
                if domain == "self-signed" {
                    continue;
                }
                match load_certificate(cert_dir, domain) {
                    Ok(Some(ck)) => {
                        self.resolver.set_cert(domain, ck);
                        tracing::info!("Loaded cached certificate for {}", domain);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("Failed to load cached cert for {}: {}", domain, e);
                    }
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

fn generate_self_signed_cert(extra_sans: &[String]) -> Result<(String, String)> {
    let mut params = CertificateParams::default();

    let mut sans = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress([127, 0, 0, 1].into()),
    ];
    for san in extra_sans {
        if let Ok(ip) = san.parse::<std::net::IpAddr>() {
            sans.push(rcgen::SanType::IpAddress(ip));
        } else {
            sans.push(rcgen::SanType::DnsName(san.clone()));
        }
    }

    params.subject_alt_names = sans;

    let cert = Certificate::from_params(params).context("Failed to generate certificate")?;
    let cert_pem = cert
        .serialize_pem()
        .context("Failed to serialize certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem, key_pem))
}
