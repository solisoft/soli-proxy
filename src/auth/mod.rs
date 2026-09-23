use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One `@auth:user:hash` entry on a route.
///
/// The hash is never serialized (so `GET /api/v1/routes` does not leak it) but
/// it *is* deserialized: a plain `#[serde(skip)]` also skipped it on input, so
/// every route arriving through the admin API had `hash == ""`, the empty hash
/// was written to `proxy.conf` as `@auth:user:`, and the next reload silently
/// dropped the entry — editing a protected route removed its protection.
///
/// Contract with the admin API: `hash: ""` (or a missing field) on an entry
/// whose username already exists on the rule being replaced means "keep the
/// existing hash"; an empty hash for a new username is rejected.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    pub username: String,
    #[serde(default, skip_serializing)]
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

/// The bcrypt cost encoded in a hash (`$2b$12$...` -> 12), or `DEFAULT_COST`
/// when the string is not one we recognise.
pub fn cost_of(hash: &str) -> u32 {
    hash.split('$')
        .nth(2)
        .and_then(|cost| cost.parse().ok())
        .unwrap_or(DEFAULT_COST)
}

/// The timing equalizer, at a chosen cost.
///
/// ⚠️ `dummy_hash()` is fixed at `DEFAULT_COST`, and that is only sound while
/// every configured account is hashed at that cost too. An operator who lowers
/// the cost of a gate — a staging password does not need 300 ms of key
/// stretching — would otherwise make an unknown username measurably *slower*
/// than a known one, which is exactly the enumeration this equalizer exists to
/// prevent. So the dummy follows the accounts.
///
/// Hashes are memoized per cost: generating one is itself a full bcrypt.
pub fn dummy_hash_at(cost: u32) -> String {
    static HASHES: std::sync::LazyLock<parking_lot::Mutex<HashMap<u32, String>>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

    if let Some(hash) = HASHES.lock().get(&cost) {
        return hash.clone();
    }
    let hash = hash_password("soli-proxy-timing-equalizer", cost);
    HASHES.lock().insert(cost, hash.clone());
    hash
}

/// How long a credential stays believed once bcrypt has vouched for it.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Above this many remembered credentials the cache is emptied wholesale.
/// A reverse proxy serves a handful of accounts, not a user base; reaching this
/// means something is hammering the gate, and forgetting everything is the
/// cheapest sane answer.
const CACHE_CAPACITY: usize = 4096;

/// Run `verify` unless this exact credential was already verified recently.
///
/// ⚠️ **Only successes are remembered, and that is the whole design.** bcrypt
/// is slow on purpose: it is what makes guessing passwords expensive. Caching
/// failures would hand an attacker a fast path to try millions of them. A wrong
/// password therefore always pays the full cost, while the operator who is
/// simply browsing pays it once.
///
/// The key is a digest of the `Authorization` header **and** of the accounts
/// configured on the route, so rotating a password invalidates what was
/// remembered instead of leaving the old one working for another five minutes.
/// Digesting also means the plaintext credential is not what we keep in memory.
pub fn verify_once(
    accounts_fingerprint: &[u8],
    authorization: &str,
    verify: impl FnOnce() -> bool,
) -> bool {
    static SEEN: std::sync::LazyLock<parking_lot::Mutex<HashMap<[u8; 32], Instant>>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

    let mut digest = Sha256::new();
    digest.update(accounts_fingerprint);
    digest.update(b"\0");
    digest.update(authorization.as_bytes());
    let key: [u8; 32] = digest.finalize().into();

    let now = Instant::now();
    {
        let seen = SEEN.lock();
        if let Some(until) = seen.get(&key) {
            if *until > now {
                return true;
            }
        }
    }

    if !verify() {
        return false;
    }

    let mut seen = SEEN.lock();
    if seen.len() >= CACHE_CAPACITY {
        seen.clear();
    }
    seen.retain(|_, until| *until > now);
    seen.insert(key, now + CACHE_TTL);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_is_read_from_the_hash() {
        assert_eq!(cost_of("$2b$12$abcdefghijklmnopqrstuv"), 12);
        assert_eq!(cost_of("$2b$08$abcdefghijklmnopqrstuv"), 8);
        // Pas un hash bcrypt : on retombe sur le defaut plutot que de paniquer.
        assert_eq!(cost_of("pas-un-hash"), DEFAULT_COST);
    }

    #[test]
    fn the_timing_equalizer_follows_the_accounts_cost() {
        // Sans cela, abaisser le cout d'une porte rendrait l'utilisateur
        // inconnu plus lent que l'utilisateur connu, et l'enumeration
        // reviendrait par la porte de derriere.
        assert_eq!(cost_of(&dummy_hash_at(6)), 6);
        assert_eq!(cost_of(&dummy_hash_at(8)), 8);
    }

    #[test]
    fn a_verified_credential_is_not_verified_twice() {
        let mut calls = 0;
        for _ in 0..3 {
            assert!(verify_once(b"comptes", "Basic dXNlcjpib24=", || {
                calls += 1;
                true
            }));
        }
        assert_eq!(calls, 1, "bcrypt doit tourner une fois, pas trois");
    }

    #[test]
    fn a_rejected_credential_pays_the_price_every_time() {
        // ⚠️ La propriete qui tient tout : memoriser les echecs offrirait a un
        // attaquant un chemin rapide vers des millions d'essais. bcrypt est
        // lent exprès, et il doit le rester pour qui se trompe.
        let mut calls = 0;
        for _ in 0..3 {
            assert!(!verify_once(b"comptes", "Basic dXNlcjptYXV2YWlz", || {
                calls += 1;
                false
            }));
        }
        assert_eq!(calls, 3, "un mot de passe faux doit repayer a chaque fois");
    }

    #[test]
    fn rotating_a_password_forgets_what_was_remembered() {
        let header = "Basic dXNlcjpyb3RhdGlvbg==";
        assert!(verify_once(b"ancien-hash", header, || true));

        let mut calls = 0;
        assert!(verify_once(b"nouveau-hash", header, || {
            calls += 1;
            true
        }));
        assert_eq!(calls, 1, "l'empreinte des comptes fait partie de la cle");
    }

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
