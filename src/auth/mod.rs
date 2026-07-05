use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    #[serde(skip)]
    pub hash: String,
}

pub fn hash_password(password: &str, cost: u32) -> String {
    hash(password, cost).expect("Failed to hash password")
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    verify(password, hash).unwrap_or(false)
}

pub fn generate_hash(password: &str) -> String {
    hash_password(password, DEFAULT_COST)
}

/// A valid bcrypt hash (at `DEFAULT_COST`) of a fixed throwaway value, computed
/// once on first use.
///
/// Used to equalize authentication timing: when a supplied username matches no
/// configured account, callers still run one `verify_password` against this
/// hash. Because bcrypt dominates the cost of a credential check, this stops
/// response timing from revealing whether a username exists (user enumeration).
/// The hash must be valid and at the same cost as real hashes — otherwise
/// `verify_password` would bail out early and the timing would not match.
pub fn dummy_hash() -> &'static str {
    static HASH: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| generate_hash("soli-proxy-timing-equalizer"));
    &HASH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "secret123";
        let hash = generate_hash(password);
        assert!(!hash.is_empty());
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrongpassword", &hash));
    }

    #[test]
    fn test_different_hashes_same_password() {
        let password = "secret123";
        let hash1 = generate_hash(password);
        let hash2 = generate_hash(password);
        assert_ne!(hash1, hash2);
        assert!(verify_password(password, &hash1));
        assert!(verify_password(password, &hash2));
    }
}
