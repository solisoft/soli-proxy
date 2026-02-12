use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
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
