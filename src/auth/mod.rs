use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

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

/// Lowest bcrypt cost a configured hash may carry (bcrypt's own floor).
pub const MIN_COST: u32 = 4;

/// Highest bcrypt cost a configured hash may carry.
///
/// ⚠️ **The cost is a work factor chosen by whoever wrote the hash**, and every
/// step doubles it: 12 is ~250 ms, 13 is ~500 ms, 20 is over a minute and 31 is
/// days — per request, and per *wrong* request, since failures are never
/// cached. In multi-tenant mode the hash in `app.infos` is written by a tenant,
/// so without a ceiling one `$2b$31$…` line pins a CPU for as long as anyone
/// keeps knocking. 13 leaves room above the default (12) for an operator who
/// wants it, and no further.
pub const MAX_COST: u32 = 13;

/// Why a configured password hash was refused. See [`validate_hash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// Not a `$2a$` / `$2b$` / `$2x$` / `$2y$` bcrypt hash of the right shape.
    Malformed,
    /// A well-formed bcrypt hash whose cost is outside `MIN_COST..=MAX_COST`.
    CostOutOfRange(u32),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::Malformed => write!(
                f,
                "not a bcrypt hash (expected $2b$NN$ followed by 53 characters; \
                 generate one with `hash-password`)"
            ),
            HashError::CostOutOfRange(cost) => write!(
                f,
                "bcrypt cost {} is outside the accepted range {}..={}",
                cost, MIN_COST, MAX_COST
            ),
        }
    }
}

impl std::error::Error for HashError {}

/// Check that `hash` is a bcrypt hash this proxy is willing to verify against,
/// and return its cost.
///
/// Every hash that enters the proxy goes through here — a route's `@auth:`,
/// an app's `[auth.users]`, a cluster push, the admin credential — and
/// [`verify_password`] re-checks it, so a hash that slipped past a loader is
/// refused instead of being handed to bcrypt. Two things are refused:
///
/// - **a malformed hash**: `$2a$`, `$2b$`, `$2x$` or `$2y$`, a two-digit cost,
///   `$`, then exactly 53 characters of bcrypt's base64 alphabet (22 of salt,
///   31 of digest). Anything else can never match a password, so it is a
///   configuration error, not an account;
/// - **a cost outside `MIN_COST..=MAX_COST`** (4 to 13). See [`MAX_COST`].
pub fn validate_hash(hash: &str) -> Result<u32, HashError> {
    let rest = hash.strip_prefix('$').ok_or(HashError::Malformed)?;
    let (version, rest) = rest.split_once('$').ok_or(HashError::Malformed)?;
    if !matches!(version, "2a" | "2b" | "2x" | "2y") {
        return Err(HashError::Malformed);
    }
    let (cost, body) = rest.split_once('$').ok_or(HashError::Malformed)?;
    if cost.len() != 2 || !cost.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HashError::Malformed);
    }
    if body.len() != 53
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
    {
        return Err(HashError::Malformed);
    }
    let cost: u32 = cost.parse().map_err(|_| HashError::Malformed)?;
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        return Err(HashError::CostOutOfRange(cost));
    }
    Ok(cost)
}

pub fn hash_password(password: &str, cost: u32) -> String {
    hash(password, cost).expect("Failed to hash password")
}

/// Whether `password` matches `hash`.
///
/// A hash [`validate_hash`] refuses never reaches bcrypt: it answers `false`
/// at once. That is the backstop for every loader — a `$2b$31$` hash that got
/// in anyway costs nothing instead of days of CPU.
///
/// ⚠️ Synchronous and slow (~250 ms at cost 12) by design. On the request path
/// go through [`verify_basic`], which runs it on the bounded blocking pool;
/// calling it directly from an async handler parks a tokio worker.
pub fn verify_password(password: &str, hash: &str) -> bool {
    if validate_hash(hash).is_err() {
        return false;
    }
    verify(password, hash).unwrap_or(false)
}

pub fn generate_hash(password: &str) -> String {
    hash_password(password, DEFAULT_COST)
}

/// The throwaway value the timing equalizer hashes.
const EQUALIZER: &str = "soli-proxy-timing-equalizer";

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
    dummy_hash_at(DEFAULT_COST)
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
/// One `OnceLock` per accepted cost: generating a hash is itself a full bcrypt,
/// and the lock makes concurrent first callers wait for the one computing it
/// instead of each computing their own (which, under a burst of unknown
/// usernames, multiplied the very work this is meant to bound). A cost outside
/// `MIN_COST..=MAX_COST` falls back to `DEFAULT_COST` — such an account can
/// never match anyway (see [`verify_password`]), and the cost is never taken
/// from untrusted input unchecked.
///
/// Blocks for one bcrypt on the first call per cost: call it from the blocking
/// pool, as [`verify_basic`] does.
pub fn dummy_hash_at(cost: u32) -> &'static str {
    const SLOTS: usize = (MAX_COST - MIN_COST + 1) as usize;
    static HASHES: [OnceLock<String>; SLOTS] = [const { OnceLock::new() }; SLOTS];

    let cost = if (MIN_COST..=MAX_COST).contains(&cost) {
        cost
    } else {
        DEFAULT_COST
    };
    HASHES[(cost - MIN_COST) as usize].get_or_init(|| hash_password(EQUALIZER, cost))
}

/// How long a credential stays believed once bcrypt has vouched for it.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Above this many remembered credentials the cache is emptied wholesale.
/// A reverse proxy serves a handful of accounts, not a user base; reaching this
/// means something is hammering the gate, and forgetting everything is the
/// cheapest sane answer.
const CACHE_CAPACITY: usize = 4096;

/// How long a queued credential check may wait for a free bcrypt slot before
/// the request is answered 503.
///
/// Long enough for a burst of real logins to clear on a small machine: with
/// two slots and ~300 ms per check, the sixteenth caller in line is served
/// after about two and a half seconds. A 1 s limit turned that burst away —
/// three people logging in at once on a two-core box got a 503.
const BCRYPT_QUEUE_WAIT: Duration = Duration::from_secs(10);

/// Queued checks allowed per bcrypt slot. Past `slots × this`, a check is
/// answered 503 at once instead of joining the queue: what bounds a flood is
/// the queue's length, so it can never grow without limit, while the wait
/// above stays generous for whoever got in line.
const BCRYPT_QUEUE_PER_SLOT: usize = 16;

/// Credential checks waiting for a bcrypt slot right now.
static BCRYPT_WAITING: AtomicUsize = AtomicUsize::new(0);

/// The outcome of a credential check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The credential matches (or matched recently, see [`verify_once`]).
    Granted,
    /// Missing, malformed or wrong.
    Denied,
    /// The bcrypt queue was full, or every slot stayed busy for
    /// [`BCRYPT_QUEUE_WAIT`]: the credential was not checked. Answer 503 with `Retry-After`, never 401 — the client
    /// did nothing wrong, and a browser shown 401 would prompt for a password
    /// it already has.
    Busy,
}

/// The slots bcrypt may run in, process-wide: half the cores, at least two.
///
/// ⚠️ **bcrypt is CPU work that takes a quarter of a second, on purpose.** Run
/// on a tokio worker it parks that worker for the duration; forty-odd wrong
/// passwords a second parked them all, and the whole proxy — every site, not
/// just the protected one — stopped answering. It now runs on the blocking
/// pool, and this semaphore bounds how many run at once, so a flood of guesses
/// costs at most half the machine and the other half keeps serving.
fn bcrypt_slots() -> &'static Arc<Semaphore> {
    static SLOTS: LazyLock<Arc<Semaphore>> =
        LazyLock::new(|| Arc::new(Semaphore::new(bcrypt_slot_count())));
    &SLOTS
}

fn bcrypt_slot_count() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    (cores / 2).max(2)
}

/// One place in the bcrypt queue, released when the check gets a slot or
/// gives up.
struct QueuePlace;

impl QueuePlace {
    fn take() -> Option<Self> {
        let limit = bcrypt_slot_count() * BCRYPT_QUEUE_PER_SLOT;
        BCRYPT_WAITING
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
            .ok()
            .map(|_| QueuePlace)
    }
}

impl Drop for QueuePlace {
    fn drop(&mut self) {
        BCRYPT_WAITING.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Run a bcrypt operation off the async workers, bounded by [`bcrypt_slots`].
///
/// Returns `None` — the caller answers 503 — when the queue already holds
/// [`BCRYPT_QUEUE_PER_SLOT`] checks per slot, when no slot frees up within
/// [`BCRYPT_QUEUE_WAIT`], or if the work panicked. The slot is held by the blocking task itself, so a client that
/// disconnects mid-check does not free it early: what is bounded is CPU actually
/// in use, not requests still listening.
pub async fn run_bcrypt<T, F>(work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = match bcrypt_slots().clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let place = QueuePlace::take()?;
            let permit =
                tokio::time::timeout(BCRYPT_QUEUE_WAIT, bcrypt_slots().clone().acquire_owned())
                    .await
                    .ok()?
                    .ok()?;
            drop(place);
            permit
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .ok()
}

/// The success cache, keyed by [`cache_key`].
static SEEN: LazyLock<parking_lot::Mutex<HashMap<[u8; 32], Instant>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// Digest of the configured accounts **and** of the `Authorization` header.
///
/// The accounts are streamed into the hasher rather than concatenated into a
/// buffer first: this runs on every request to a protected route, cache hit or
/// not, and a few hundred bytes of SHA-256 is cheaper than the allocation it
/// replaced. It stays a function of the hashes themselves, so rotating a
/// password changes the key and forgets what was remembered.
fn cache_key(accounts: &[BasicAuth], authorization: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    for account in accounts {
        digest.update(account.username.as_bytes());
        digest.update(b"\0");
        digest.update(account.hash.as_bytes());
        digest.update(b"\0");
    }
    digest.update(b"\0");
    digest.update(authorization.as_bytes());
    digest.finalize().into()
}

fn recently_verified(key: &[u8; 32]) -> bool {
    SEEN.lock()
        .get(key)
        .is_some_and(|until| *until > Instant::now())
}

fn remember(key: [u8; 32]) {
    let now = Instant::now();
    let mut seen = SEEN.lock();
    if seen.len() >= CACHE_CAPACITY {
        seen.clear();
    }
    seen.retain(|_, until| *until > now);
    seen.insert(key, now + CACHE_TTL);
}

/// Run `verify` on the bcrypt pool unless this exact credential was already
/// verified recently against these exact accounts.
///
/// ⚠️ **Only successes are remembered, and that is the whole design.** bcrypt
/// is slow on purpose: it is what makes guessing passwords expensive. Caching
/// failures would hand an attacker a fast path to try millions of them. A wrong
/// password therefore always pays the full cost, while the operator who is
/// simply browsing pays it once.
///
/// The key covers the `Authorization` header **and** the accounts configured
/// on the route (see [`cache_key`]), so rotating a password invalidates what
/// was remembered instead of leaving the old one working for another five
/// minutes. Digesting also means the plaintext credential is not what we keep
/// in memory.
///
/// A cache hit never touches the bcrypt pool, so a flood of wrong passwords
/// saturating it does not lock out someone who already logged in.
pub async fn verify_once<F>(accounts: &[BasicAuth], authorization: &str, verify: F) -> Verdict
where
    F: FnOnce() -> bool + Send + 'static,
{
    let key = cache_key(accounts, authorization);
    if recently_verified(&key) {
        return Verdict::Granted;
    }
    match run_bcrypt(verify).await {
        None => Verdict::Busy,
        Some(false) => Verdict::Denied,
        Some(true) => {
            remember(key);
            Verdict::Granted
        }
    }
}

/// Whether this exact credential was verified against these exact accounts
/// within the cache TTL — a lookup only, no bcrypt.
///
/// For callers that must refuse to run bcrypt (a client over its failure
/// budget) but should still let an already-verified session through.
pub fn is_remembered(accounts: &[BasicAuth], authorization: &str) -> bool {
    recently_verified(&cache_key(accounts, authorization))
}

/// Constant-time byte comparison, so the username check does not leak where
/// (or whether) a guess diverges.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Check an `Authorization: Basic …` header against `accounts`.
///
/// The one implementation behind route `@auth`, app `[auth]`, cluster-pushed
/// auth and the admin API's Basic credential:
///
/// - the username is located with a constant-time compare, without breaking
///   early, so the loop's timing does not depend on which entry matched;
/// - exactly one bcrypt runs either way — against the matched hash, or against
///   a dummy at the accounts' own cost when the username is unknown — so a
///   wrong username and a wrong password take the same time;
/// - it runs on the bounded blocking pool ([`run_bcrypt`]), and only successes
///   are cached ([`verify_once`]).
///
/// `accounts` empty means nobody can get in: callers decide beforehand whether
/// a request needs credentials at all.
pub async fn verify_basic(accounts: &[BasicAuth], authorization: Option<&str>) -> Verdict {
    let Some(header) = authorization else {
        return Verdict::Denied;
    };
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return Verdict::Denied;
    };
    if accounts.is_empty() {
        return Verdict::Denied;
    }
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .unwrap_or_default();
    let creds = String::from_utf8_lossy(&decoded);
    let Some((username, password)) = creds.split_once(':') else {
        return Verdict::Denied;
    };

    let mut matched: Option<String> = None;
    for account in accounts {
        if constant_time_eq(account.username.as_bytes(), username.as_bytes()) {
            matched = Some(account.hash.clone());
        }
    }
    // The dummy follows the accounts' own cost, otherwise lowering a gate's
    // cost would make the unknown-user path slower than the known one and give
    // the enumeration back.
    let cost = validate_hash(&accounts[0].hash).unwrap_or(DEFAULT_COST);
    let password = password.to_owned();

    verify_once(accounts, header, move || {
        let hash = matched.as_deref().unwrap_or_else(|| dummy_hash_at(cost));
        let password_ok = verify_password(&password, hash);
        matched.is_some() && password_ok
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A well-formed hash at `cost` (the digest is junk; only the shape counts).
    fn shaped(cost: &str) -> String {
        format!("$2b${}${}", cost, "a".repeat(53))
    }

    fn account(username: &str, hash: &str) -> Vec<BasicAuth> {
        vec![BasicAuth {
            username: username.to_string(),
            hash: hash.to_string(),
        }]
    }

    fn basic(user: &str, password: &str) -> String {
        let raw = format!("{user}:{password}");
        format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw)
        )
    }

    #[test]
    fn cost_is_read_from_the_hash() {
        assert_eq!(cost_of("$2b$12$abcdefghijklmnopqrstuv"), 12);
        assert_eq!(cost_of("$2b$08$abcdefghijklmnopqrstuv"), 8);
        // Pas un hash bcrypt : on retombe sur le defaut plutot que de paniquer.
        assert_eq!(cost_of("pas-un-hash"), DEFAULT_COST);
    }

    #[test]
    fn a_real_hash_validates_and_reports_its_cost() {
        assert_eq!(validate_hash(&hash_password("x", 4)), Ok(4));
        for version in ["2a", "2b", "2x", "2y"] {
            let hash = format!("${}$10${}", version, "./AZaz09".repeat(7).split_at(53).0);
            assert_eq!(validate_hash(&hash), Ok(10), "{hash}");
        }
    }

    #[test]
    fn a_tenant_cannot_pick_a_cost_that_takes_hours() {
        // `$2b$31$` : des jours de CPU par requete, mot de passe faux compris.
        assert_eq!(
            validate_hash(&shaped("31")),
            Err(HashError::CostOutOfRange(31))
        );
        assert_eq!(
            validate_hash(&shaped("14")),
            Err(HashError::CostOutOfRange(14))
        );
        assert_eq!(
            validate_hash(&shaped("03")),
            Err(HashError::CostOutOfRange(3))
        );
        assert_eq!(validate_hash(&shaped("13")), Ok(13));
        assert_eq!(validate_hash(&shaped("04")), Ok(4));
    }

    #[test]
    fn malformed_hashes_are_refused() {
        for bad in [
            "",
            "plaintext",
            "$2b$12$short",
            "$2b$12$adminhash",
            "$1$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "$2b$1$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "$2b$+9$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
            "$2b$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(validate_hash(bad), Err(HashError::Malformed), "{bad:?}");
        }
    }

    #[test]
    fn an_out_of_range_hash_is_never_handed_to_bcrypt() {
        // Le filet de securite derriere chaque chargeur : meme un hash qui
        // aurait echappe a la validation ne coute rien.
        let started = Instant::now();
        assert!(!verify_password("x", &shaped("31")));
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn the_timing_equalizer_follows_the_accounts_cost() {
        // Sans cela, abaisser le cout d'une porte rendrait l'utilisateur
        // inconnu plus lent que l'utilisateur connu, et l'enumeration
        // reviendrait par la porte de derriere.
        assert_eq!(cost_of(dummy_hash_at(6)), 6);
        assert_eq!(cost_of(dummy_hash_at(8)), 8);
        // Hors bornes : jamais calcule tel quel.
        assert_eq!(cost_of(dummy_hash_at(31)), DEFAULT_COST);
    }

    #[test]
    fn concurrent_first_callers_share_one_dummy() {
        let hashes: Vec<&'static str> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4).map(|_| scope.spawn(|| dummy_hash_at(5))).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(hashes.windows(2).all(|w| std::ptr::eq(w[0], w[1])));
    }

    #[tokio::test]
    async fn a_verified_credential_is_not_verified_twice() {
        let calls = Arc::new(AtomicUsize::new(0));
        let accounts = account("user", "comptes");
        for _ in 0..3 {
            let calls = calls.clone();
            let verdict = verify_once(&accounts, "Basic dXNlcjpib24=", move || {
                calls.fetch_add(1, Ordering::SeqCst);
                true
            })
            .await;
            assert_eq!(verdict, Verdict::Granted);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "bcrypt doit tourner une fois, pas trois"
        );
    }

    #[tokio::test]
    async fn a_rejected_credential_pays_the_price_every_time() {
        // ⚠️ La propriete qui tient tout : memoriser les echecs offrirait a un
        // attaquant un chemin rapide vers des millions d'essais. bcrypt est
        // lent exprès, et il doit le rester pour qui se trompe.
        let calls = Arc::new(AtomicUsize::new(0));
        let accounts = account("user", "comptes");
        for _ in 0..3 {
            let calls = calls.clone();
            let verdict = verify_once(&accounts, "Basic dXNlcjptYXV2YWlz", move || {
                calls.fetch_add(1, Ordering::SeqCst);
                false
            })
            .await;
            assert_eq!(verdict, Verdict::Denied);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "un mot de passe faux doit repayer a chaque fois"
        );
    }

    #[tokio::test]
    async fn rotating_a_password_forgets_what_was_remembered() {
        let header = "Basic dXNlcjpyb3RhdGlvbg==";
        let before = account("user", "ancien-hash");
        assert_eq!(
            verify_once(&before, header, || true).await,
            Verdict::Granted
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let after = account("user", "nouveau-hash");
        let counted = calls.clone();
        let verdict = verify_once(&after, header, move || {
            counted.fetch_add(1, Ordering::SeqCst);
            true
        })
        .await;
        assert_eq!(verdict, Verdict::Granted);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "l'empreinte des comptes fait partie de la cle"
        );
    }

    #[tokio::test]
    async fn verify_basic_checks_user_and_password() {
        let accounts = account("alice", &hash_password("s3cret", 4));
        let ok = basic("alice", "s3cret");
        assert_eq!(verify_basic(&accounts, Some(&ok)).await, Verdict::Granted);
        for wrong in [basic("alice", "nope"), basic("bob", "s3cret")] {
            assert_eq!(verify_basic(&accounts, Some(&wrong)).await, Verdict::Denied);
        }
        assert_eq!(verify_basic(&accounts, None).await, Verdict::Denied);
        assert_eq!(
            verify_basic(&accounts, Some("Bearer x")).await,
            Verdict::Denied
        );
        assert_eq!(
            verify_basic(&accounts, Some("Basic !!!")).await,
            Verdict::Denied
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bcrypt_does_not_run_on_the_async_workers() {
        // Le gel d'origine : bcrypt sur un worker tokio. Ici, pendant qu'une
        // rafale de mauvais mots de passe tourne (8 x ~150 ms, soit ~600 ms de
        // travail pour deux workers), un minuteur de 10 ms sur le runtime doit
        // continuer a tomber a l'heure.
        let accounts = Arc::new(account("alice", &hash_password("s3cret", 11)));
        let mut checks = Vec::new();
        for i in 0..8 {
            let accounts = accounts.clone();
            checks.push(tokio::spawn(async move {
                let header = basic("alice", &format!("wrong-{i}"));
                verify_basic(&accounts, Some(&header)).await
            }));
        }
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "the runtime stalled for {:?} while bcrypt ran",
            started.elapsed()
        );
        for check in checks {
            assert_ne!(check.await.unwrap(), Verdict::Granted);
        }
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
