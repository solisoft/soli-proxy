use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::RwLock;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::ServerConfig;

use crate::config::LetsEncryptConfig;

/// Shared store for ACME HTTP-01 challenge tokens.
/// Maps token -> key_authorization.
pub type ChallengeStore = Arc<RwLock<HashMap<String, String>>>;

pub fn new_challenge_store() -> ChallengeStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Dynamic certificate resolver that supports per-domain ACME certs
/// with a self-signed fallback.
pub struct AcmeCertResolver {
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    fallback: RwLock<Option<Arc<CertifiedKey>>>,
}

impl fmt::Debug for AcmeCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let domain_count = self.certs.read().map(|c| c.len()).unwrap_or(0);
        let has_fallback = self.fallback.read().map(|f| f.is_some()).unwrap_or(false);
        f.debug_struct("AcmeCertResolver")
            .field("domains", &domain_count)
            .field("has_fallback", &has_fallback)
            .finish()
    }
}

impl Default for AcmeCertResolver {
    fn default() -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
            fallback: RwLock::new(None),
        }
    }
}

impl AcmeCertResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_fallback(&self, key: Arc<CertifiedKey>) {
        if let Ok(mut fallback) = self.fallback.write() {
            *fallback = Some(key);
        }
    }

    pub fn set_cert(&self, domain: &str, key: Arc<CertifiedKey>) {
        if let Ok(mut certs) = self.certs.write() {
            certs.insert(domain.to_string(), key);
        }
    }
}

impl ResolvesServerCert for AcmeCertResolver {
    fn resolve(
        &self,
        client_hello: tokio_rustls::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            if let Ok(certs) = self.certs.read() {
                if let Some(key) = certs.get(sni) {
                    return Some(key.clone());
                }
            }
        }

        if let Ok(fallback) = self.fallback.read() {
            return fallback.clone();
        }

        None
    }
}

/// Build a ServerConfig using the AcmeCertResolver.
pub fn build_server_config(resolver: Arc<AcmeCertResolver>) -> Result<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Get or create an ACME account, persisting credentials to disk.
pub async fn get_or_create_account(
    le_config: &LetsEncryptConfig,
    cache_dir: &Path,
) -> Result<Account> {
    let creds_path = cache_dir.join("account_credentials.json");

    if creds_path.exists() {
        let json = std::fs::read_to_string(&creds_path)
            .context("Failed to read ACME account credentials")?;
        let credentials: AccountCredentials =
            serde_json::from_str(&json).context("Failed to parse ACME account credentials")?;
        let account = Account::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create account builder: {:?}", e))?
            .from_credentials(credentials)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to restore ACME account: {:?}", e))?;
        tracing::info!("Restored ACME account from {}", creds_path.display());
        return Ok(account);
    }

    let directory_url = if le_config.staging {
        LetsEncrypt::Staging.url().to_string()
    } else {
        LetsEncrypt::Production.url().to_string()
    };

    let contact = format!("mailto:{}", le_config.email);
    let (account, credentials) = Account::builder()
        .map_err(|e| anyhow::anyhow!("Failed to create account builder: {:?}", e))?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: le_config.terms_agreed,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ACME account: {:?}", e))?;

    std::fs::create_dir_all(cache_dir)?;
    let json = serde_json::to_string_pretty(&credentials)?;
    std::fs::write(&creds_path, &json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!(
        "Created new ACME account, credentials saved to {}",
        creds_path.display()
    );
    Ok(account)
}

/// Issue a certificate for the given domains using HTTP-01 challenges.
pub async fn issue_certificate(
    account: &Account,
    domains: &[String],
    challenge_store: &ChallengeStore,
) -> Result<(String, String)> {
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create ACME order: {:?}", e))?;

    // Collect challenge tokens to clean up later
    let mut challenge_tokens: Vec<String> = Vec::new();

    // Process authorizations using the stream-like API
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz =
                result.map_err(|e| anyhow::anyhow!("Failed to get authorization: {:?}", e))?;

            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found"))?;

            let key_auth = challenge.key_authorization();
            let key_auth_str = key_auth.as_str().to_string();
            let token = challenge.token.clone();

            // Store challenge for the HTTP server to serve
            {
                let mut store = challenge_store
                    .write()
                    .map_err(|_| anyhow::anyhow!("Challenge store poisoned"))?;
                store.insert(token.clone(), key_auth_str);
            }

            challenge_tokens.push(token.clone());
            tracing::info!("ACME challenge set for token: {}", token);

            // Signal that we're ready for validation
            challenge
                .set_ready()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to set challenge ready: {:?}", e))?;
        }
    }

    // Poll until order is ready
    let status = order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await
        .map_err(|e| anyhow::anyhow!("ACME order failed to become ready: {:?}", e))?;

    if status != OrderStatus::Ready {
        anyhow::bail!("ACME order not ready, status: {:?}", status);
    }

    // Finalize order — generates private key and CSR automatically
    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to finalize ACME order: {:?}", e))?;

    // Get cert chain
    let cert_chain_pem = order
        .certificate()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to retrieve certificate: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("No certificate returned"))?;

    // Clean up challenge tokens
    {
        let mut store = challenge_store
            .write()
            .map_err(|_| anyhow::anyhow!("Challenge store poisoned"))?;
        for token in &challenge_tokens {
            store.remove(token);
        }
    }

    Ok((cert_chain_pem, private_key_pem))
}

/// Save certificate and key PEM files to disk.
pub fn save_certificate(
    cache_dir: &Path,
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    std::fs::create_dir_all(cache_dir)?;

    let cert_path = cache_dir.join(format!("{}.cert.pem", domain));
    let key_path = cache_dir.join(format!("{}.key.pem", domain));

    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!(
        "Saved certificate for {} to {}",
        domain,
        cert_path.display()
    );
    Ok(())
}

/// Load certificate and key from PEM files on disk.
pub fn load_certificate(cache_dir: &Path, domain: &str) -> Result<Option<Arc<CertifiedKey>>> {
    let cert_path = cache_dir.join(format!("{}.cert.pem", domain));
    let key_path = cache_dir.join(format!("{}.key.pem", domain));

    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let ck = certified_key_from_pem(&std::fs::read(&cert_path)?, &std::fs::read(&key_path)?)?;

    Ok(Some(Arc::new(ck)))
}

/// Parse PEM-encoded cert chain and private key into a CertifiedKey.
pub fn certified_key_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &*key_pem)
        .context("Failed to parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in PEM"))?;

    let provider = tokio_rustls::rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("No default CryptoProvider installed"))?;

    let certified_key = CertifiedKey::from_der(certs, key, provider)
        .map_err(|e| anyhow::anyhow!("Failed to build CertifiedKey: {:?}", e))?;

    Ok(certified_key)
}

/// Check if a certificate for the given domain expires within 30 days.
pub fn cert_expires_soon(cache_dir: &Path, domain: &str) -> bool {
    let cert_path = cache_dir.join(format!("{}.cert.pem", domain));

    if !cert_path.exists() {
        return true;
    }

    let cert_pem = match std::fs::read(&cert_path) {
        Ok(data) => data,
        Err(_) => return true,
    };

    let certs: Vec<CertificateDer<'static>> =
        match rustls_pemfile::certs(&mut &*cert_pem).collect::<std::result::Result<Vec<_>, _>>() {
            Ok(c) if !c.is_empty() => c,
            _ => return true,
        };

    match x509_parser::parse_x509_certificate(&certs[0]) {
        Ok((_, cert)) => {
            let not_after = cert.validity().not_after.timestamp();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let thirty_days = 30 * 24 * 3600;
            not_after - now < thirty_days
        }
        Err(_) => true,
    }
}

/// Spawn a background task that checks and renews certificates every 12 hours.
pub fn spawn_renewal_task(
    account: Account,
    domains: Vec<String>,
    cache_dir: PathBuf,
    challenge_store: ChallengeStore,
    resolver: Arc<AcmeCertResolver>,
) {
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(12 * 3600);

        loop {
            tokio::time::sleep(interval).await;

            tracing::info!("ACME renewal check: examining {} domain(s)", domains.len());

            for domain in &domains {
                if !cert_expires_soon(&cache_dir, domain) {
                    tracing::debug!("Certificate for {} is still valid", domain);
                    continue;
                }

                tracing::info!("Certificate for {} needs renewal, issuing...", domain);

                match issue_certificate(&account, std::slice::from_ref(domain), &challenge_store)
                    .await
                {
                    Ok((cert_pem, key_pem)) => {
                        if let Err(e) = save_certificate(&cache_dir, domain, &cert_pem, &key_pem) {
                            tracing::error!("Failed to save renewed cert for {}: {}", domain, e);
                            continue;
                        }

                        match certified_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()) {
                            Ok(ck) => {
                                resolver.set_cert(domain, Arc::new(ck));
                                tracing::info!("Successfully renewed certificate for {}", domain);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to parse renewed cert for {}: {}",
                                    domain,
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to renew certificate for {}: {}", domain, e);
                    }
                }
            }
        }
    });
}
