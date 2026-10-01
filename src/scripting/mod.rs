use mlua::{Function, Lua, Result as LuaResult, Table, Value};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Represents a request as seen by Lua scripts.
#[derive(Clone, Debug)]
pub struct LuaRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub host: String,
    pub content_length: u64,
}

/// Result of calling on_request — either continue or deny early.
#[derive(Debug)]
pub enum RequestHookResult {
    Continue(LuaRequest),
    Deny { status: u16, body: String },
}

/// Result of calling on_route — override, keep default, or deny because the
/// hook itself failed. A failing on_route may be doing authz-sensitive
/// backend selection, so an error must not silently fall back to the
/// default target.
#[derive(Debug)]
pub enum RouteHookResult {
    Override(String),
    Default,
    Deny { status: u16, body: String },
}

/// Status/body returned to the client when a request-path hook (on_request,
/// on_route) raises a Lua error. Hooks fail closed: an error must deny, not
/// let the request through with whatever checks the script did not finish.
const SCRIPT_ERROR_STATUS: u16 = 500;
const SCRIPT_ERROR_BODY: &str = "script error";

/// Per-call execution deadline read by the instruction-count hook. Stored
/// in the Lua app-data slot and refreshed immediately before every hook
/// invocation (see `arm_hook_timeout`).
struct HookDeadline(Instant);

/// Modifications returned by on_response hook.
#[derive(Debug, Default)]
pub struct ResponseMod {
    pub set_headers: HashMap<String, String>,
    pub remove_headers: Vec<String>,
    pub replace_body: Option<String>,
    pub override_status: Option<u16>,
}

/// Shared state for cross-worker counters (used by `shared` Lua module).
type SharedState = Arc<std::sync::RwLock<HashMap<String, f64>>>;

/// One pooled Lua state plus the snapshot of the globals it had once set up
/// (built-in modules, the loaded stdlib, base library functions and the
/// script's own hook functions). `cleanup_lua_state` clears every global
/// *not* in `baseline` after each hook call. The table is kept here rather
/// than in the Lua registry so the cleanup does not pay a registry lookup per
/// call, and it is keyed by the global's own key value so the comparison
/// needs no string conversion.
struct LuaSlot {
    lua: Lua,
    baseline: Table,
}

type StatePool = Vec<std::sync::Mutex<LuaSlot>>;

/// Which of the four hooks a script defines, probed once at load time so the
/// request path can skip building a request table for a script that has no
/// such hook — and skip locking one of its states at all.
#[derive(Clone, Copy, Debug, Default)]
struct HookSet {
    on_request: bool,
    on_route: bool,
    on_response: bool,
    on_request_end: bool,
}

impl HookSet {
    fn probe(lua: &Lua) -> Self {
        let has = |name: &str| lua.globals().get::<Function>(name).is_ok();
        Self {
            on_request: has("on_request"),
            on_route: has("on_route"),
            on_response: has("on_response"),
            on_request_end: has("on_request_end"),
        }
    }

    fn has(&self, hook: Hook) -> bool {
        match hook {
            Hook::Request => self.on_request,
            Hook::Route => self.on_route,
            Hook::Response => self.on_response,
            Hook::RequestEnd => self.on_request_end,
        }
    }
}

/// The four request-lifecycle hooks a script may define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `on_request(req)`
    Request,
    /// `on_route(req, target)`
    Route,
    /// `on_response(req, resp)`
    Response,
    /// `on_request_end(req, resp, duration_ms, target)`
    RequestEnd,
}

/// A route script's per-worker states and the hooks it defines.
struct RouteScript {
    states: StatePool,
    hooks: HookSet,
}

/// The Lua scripting engine. Thread-safe, cheaply cloneable.
///
/// Holds a pool of pre-initialized Lua states (one per worker) for global scripts,
/// plus per-script pools for route-specific scripts.
#[derive(Clone)]
pub struct LuaEngine {
    inner: Arc<LuaEngineInner>,
}

struct LuaEngineInner {
    /// Global hook pool — all .lua files from scripts_dir loaded together
    states: StatePool,
    hooks: HookSet,
    /// Max execution time per hook call; re-armed before every invocation.
    hook_timeout: Duration,
    /// Per-script hook pool (script_name -> per-worker Lua states)
    route_scripts: HashMap<String, RouteScript>,
    /// Whether any route script defines `on_response` / `on_request_end`, so
    /// the proxy knows up front whether it must keep a copy of the request
    /// for those late hooks.
    any_route_on_response: bool,
    any_route_on_request_end: bool,
    /// Shared state for cross-worker counters (kept alive via Arc)
    _shared_state: SharedState,
}

impl LuaEngine {
    /// Create a new LuaEngine by loading all .lua files from `scripts_dir`.
    ///
    /// `num_states` should match the number of worker threads.
    /// `hook_timeout` is the max execution time per hook call.
    /// `exposed_env` is an allowlist of environment variable names that Lua scripts can access via `env.get()`.
    pub fn new(
        scripts_dir: &Path,
        num_states: usize,
        hook_timeout: Duration,
        exposed_env: &[String],
    ) -> anyhow::Result<Self> {
        let num_states = num_states.max(1);
        let shared_state: SharedState = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Collect all .lua files from the scripts directory
        let mut script_sources: Vec<(String, String)> = Vec::new();
        if scripts_dir.exists() && scripts_dir.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(scripts_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "lua")
                        .unwrap_or(false)
                })
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let path = entry.path();
                let source = std::fs::read_to_string(&path)?;
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                tracing::info!("Loading Lua script: {}", name);
                script_sources.push((name, source));
            }
        }

        if script_sources.is_empty() {
            tracing::info!("No Lua scripts found in {}", scripts_dir.display());
        }

        // Create the first Lua state to probe which hooks exist
        let probe_lua =
            Self::create_lua_state(&script_sources, hook_timeout, &shared_state, exposed_env)?;
        let hooks = HookSet::probe(&probe_lua.lua);

        tracing::info!(
            "Lua hooks: on_request={}, on_route={}, on_response={}, on_request_end={}",
            hooks.on_request,
            hooks.on_route,
            hooks.on_response,
            hooks.on_request_end
        );

        // Build the pool of Lua states
        let mut states = Vec::with_capacity(num_states);
        states.push(std::sync::Mutex::new(probe_lua));
        for _ in 1..num_states {
            let lua =
                Self::create_lua_state(&script_sources, hook_timeout, &shared_state, exposed_env)?;
            states.push(std::sync::Mutex::new(lua));
        }

        Ok(Self {
            inner: Arc::new(LuaEngineInner {
                states,
                hooks,
                hook_timeout,
                route_scripts: HashMap::new(),
                any_route_on_response: false,
                any_route_on_request_end: false,
                _shared_state: shared_state,
            }),
        })
    }

    /// Create a LuaEngine with per-route script support.
    ///
    /// `global_scripts` — filenames loaded into the global pool (run on every request)
    /// `route_script_names` — unique filenames that need their own per-worker pools
    /// `exposed_env` is an allowlist of environment variable names that Lua scripts can access via `env.get()`.
    pub fn with_route_scripts(
        scripts_dir: &Path,
        num_states: usize,
        hook_timeout: Duration,
        global_scripts: &[String],
        route_script_names: &[String],
        exposed_env: &[String],
    ) -> anyhow::Result<Self> {
        let num_states = num_states.max(1);
        let shared_state: SharedState = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Load global scripts
        let mut global_sources: Vec<(String, String)> = Vec::new();
        for name in global_scripts {
            let path = scripts_dir.join(name);
            if path.exists() {
                let source = std::fs::read_to_string(&path)?;
                tracing::info!("Loading global Lua script: {}", name);
                global_sources.push((name.clone(), source));
            } else {
                tracing::warn!("Global Lua script not found: {}", path.display());
            }
        }

        // Probe global hooks
        let probe_lua =
            Self::create_lua_state(&global_sources, hook_timeout, &shared_state, exposed_env)?;
        let hooks = HookSet::probe(&probe_lua.lua);

        tracing::info!(
            "Global Lua hooks: on_request={}, on_route={}, on_response={}, on_request_end={}",
            hooks.on_request,
            hooks.on_route,
            hooks.on_response,
            hooks.on_request_end
        );

        // Build global pool
        let mut states = Vec::with_capacity(num_states);
        states.push(std::sync::Mutex::new(probe_lua));
        for _ in 1..num_states {
            let lua =
                Self::create_lua_state(&global_sources, hook_timeout, &shared_state, exposed_env)?;
            states.push(std::sync::Mutex::new(lua));
        }

        // Build per-route-script pools
        let mut route_scripts: HashMap<String, RouteScript> = HashMap::new();
        for name in route_script_names {
            if global_scripts.contains(name) {
                continue;
            }
            let path = scripts_dir.join(name);

            let canonical_path = match path.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        "Route Lua script path could not be canonicalized: {}: {}",
                        path.display(),
                        e
                    );
                    continue;
                }
            };
            let canonical_scripts_dir = match scripts_dir.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        "scripts_dir could not be canonicalized: {}: {}",
                        scripts_dir.display(),
                        e
                    );
                    continue;
                }
            };
            if !canonical_path.starts_with(&canonical_scripts_dir) {
                tracing::warn!(
                    "Route Lua script path escapes scripts_dir: {}",
                    path.display()
                );
                continue;
            }

            if !path.exists() {
                tracing::warn!("Route Lua script not found: {}", path.display());
                continue;
            }
            let source = std::fs::read_to_string(&path)?;
            tracing::info!("Loading route Lua script: {}", name);
            let script_sources = vec![(name.clone(), source)];

            let mut script_states = Vec::with_capacity(num_states);
            for _ in 0..num_states {
                let lua = Self::create_lua_state(
                    &script_sources,
                    hook_timeout,
                    &shared_state,
                    exposed_env,
                )?;
                script_states.push(std::sync::Mutex::new(lua));
            }
            let script_hooks = script_states
                .first()
                .map(|m| HookSet::probe(&m.lock().unwrap_or_else(|p| p.into_inner()).lua))
                .unwrap_or_default();
            route_scripts.insert(
                name.clone(),
                RouteScript {
                    states: script_states,
                    hooks: script_hooks,
                },
            );
        }

        let any_route_on_response = route_scripts.values().any(|r| r.hooks.on_response);
        let any_route_on_request_end = route_scripts.values().any(|r| r.hooks.on_request_end);
        Ok(Self {
            inner: Arc::new(LuaEngineInner {
                states,
                hooks,
                hook_timeout,
                route_scripts,
                any_route_on_response,
                any_route_on_request_end,
                _shared_state: shared_state,
            }),
        })
    }

    fn create_lua_state(
        scripts: &[(String, String)],
        hook_timeout: Duration,
        shared_state: &SharedState,
        exposed_env: &[String],
    ) -> anyhow::Result<LuaSlot> {
        // COROUTINE is intentionally excluded: mlua's set_hook does not
        // propagate to coroutine threads, so a script could escape the
        // execution-timeout guard via `coroutine.wrap(function() while
        // true do end end)()`. Nothing in the registered hook surface
        // needs coroutines, so the simplest fix is to never load the
        // stdlib in the first place.
        let lua = Lua::new_with(
            mlua::StdLib::TABLE | mlua::StdLib::STRING | mlua::StdLib::MATH | mlua::StdLib::UTF8,
            mlua::LuaOptions::default(),
        )?;

        // Cap per-VM memory at 64 MiB. Without this, a hook can OOM the
        // host via long-running C calls that don't trip the per-instruction
        // hook (e.g. `string.rep("a", 1<<30)`, `table.concat` on a giant
        // table). The cap is generous for typical hooks but bounded.
        const LUA_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
        let _ = lua.set_memory_limit(LUA_MEMORY_LIMIT_BYTES);

        // Arm the timeout guard for the top-level chunk execution below. Hook
        // calls re-arm it per invocation (see `arm_hook_timeout`).
        Self::arm_hook_timeout(&lua, hook_timeout);

        // Register built-in modules
        Self::register_log_module(&lua)?;
        Self::register_base64_module(&lua)?;
        Self::register_crypto_module(&lua)?;
        Self::register_env_module(&lua, exposed_env)?;
        Self::register_time_module(&lua)?;
        Self::register_shared_module(&lua, shared_state)?;

        // Load all scripts in order
        for (name, source) in scripts {
            if source.starts_with('\x1B') {
                anyhow::bail!("Lua bytecode loading is disabled");
            }
            lua.load(source.as_str())
                .set_mode(mlua::ChunkMode::Text)
                .set_name(name)
                .exec()
                .map_err(|e| anyhow::anyhow!("Error loading Lua script '{}': {}", name, e))?;
        }

        // Belt-and-braces: remove dangerous globals that shouldn't be accessible
        let globals = lua.globals();
        for dangerous in &[
            "os",
            "io",
            "package",
            "dofile",
            "loadfile",
            "load",
            "loadstring",
            "require",
        ] {
            let _ = globals.set(*dangerous, mlua::Value::Nil);
        }

        // Snapshot the set of globals that exist after setup — the built-in
        // modules, the loaded stdlib (math/string/table/utf8), the base
        // library functions (tostring, pairs, …), and the script-defined hook
        // functions. cleanup_lua_state() clears every global NOT in this set
        // after each hook call, so a script cannot leak request-scoped globals
        // into the next call — without also nuking the stdlib the next call
        // needs (which would make `math.floor`, `tostring`, … fail on every
        // reused pool state after the first request).
        let baseline = lua.create_table()?;
        for pair in globals.pairs::<mlua::Value, mlua::Value>() {
            let (key, _) = pair?;
            baseline.raw_set(key, true)?;
        }
        drop(globals);

        Ok(LuaSlot { lua, baseline })
    }

    /// (Re-)arm the per-call execution timeout on a pooled state.
    ///
    /// Must be called immediately before every hook invocation. Two things
    /// are state-scoped rather than call-scoped and would otherwise go stale
    /// on a long-lived pooled state:
    ///  - the deadline: it lives in app data and is refreshed here, so the
    ///    hook closure never captures an `Instant` from state creation;
    ///  - the instruction counter: Lua 5.4's count hook accumulates across
    ///    pcalls, so `set_hook` is called again each time — `lua_sethook`
    ///    resets `hookcount`, giving every call a fresh 10,000-instruction
    ///    window before the first check.
    fn arm_hook_timeout(lua: &Lua, hook_timeout: Duration) {
        let timeout_ms = hook_timeout.as_millis() as u32;
        lua.set_app_data(HookDeadline(Instant::now() + hook_timeout));
        lua.set_hook(
            mlua::HookTriggers::new().every_nth_instruction(10000),
            move |lua, _debug| {
                // A missing deadline means the hook was not armed for this
                // call; treat that as expired rather than run unbounded.
                let expired = lua
                    .app_data_ref::<HookDeadline>()
                    .map(|d| Instant::now() >= d.0)
                    .unwrap_or(true);
                if expired {
                    return Err(mlua::Error::RuntimeError(format!(
                        "script execution timeout after {}ms",
                        timeout_ms
                    )));
                }
                Ok(mlua::VmState::Continue)
            },
        );
    }

    fn register_log_module(lua: &Lua) -> LuaResult<()> {
        let log_table = lua.create_table()?;

        log_table.set(
            "info",
            lua.create_function(|_, msg: String| {
                tracing::info!(target: "lua", "{}", msg);
                Ok(())
            })?,
        )?;

        log_table.set(
            "warn",
            lua.create_function(|_, msg: String| {
                tracing::warn!(target: "lua", "{}", msg);
                Ok(())
            })?,
        )?;

        log_table.set(
            "error",
            lua.create_function(|_, msg: String| {
                tracing::error!(target: "lua", "{}", msg);
                Ok(())
            })?,
        )?;

        log_table.set(
            "debug",
            lua.create_function(|_, msg: String| {
                tracing::debug!(target: "lua", "{}", msg);
                Ok(())
            })?,
        )?;

        lua.globals().set("log", log_table)?;
        Ok(())
    }

    fn register_base64_module(lua: &Lua) -> LuaResult<()> {
        use base64::Engine as _;

        let table = lua.create_table()?;

        table.set(
            "encode",
            lua.create_function(|_, s: String| {
                Ok(base64::engine::general_purpose::STANDARD.encode(s.as_bytes()))
            })?,
        )?;

        // Lua convention: returns `decoded` on success, `nil, err` on bad
        // input. Raising here instead would abort the calling hook with a
        // script error on attacker-controlled input (e.g. a malformed
        // Authorization header), which is exactly where it gets used.
        table.set(
            "decode",
            lua.create_function(|_, s: String| {
                match base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) {
                    Ok(bytes) => Ok((Some(String::from_utf8_lossy(&bytes).into_owned()), None)),
                    Err(e) => Ok((None, Some(format!("base64 decode error: {}", e)))),
                }
            })?,
        )?;

        lua.globals().set("base64", table)?;
        Ok(())
    }

    fn register_crypto_module(lua: &Lua) -> LuaResult<()> {
        use sha2::Digest;

        let table = lua.create_table()?;

        table.set(
            "sha256",
            lua.create_function(|_, s: String| {
                let mut hasher = sha2::Sha256::new();
                hasher.update(s.as_bytes());
                let result = hasher.finalize();
                Ok(hex_encode(&result))
            })?,
        )?;

        table.set(
            "hmac_sha256",
            lua.create_function(|_, (key, msg): (String, String)| {
                use hmac::{Hmac, Mac};
                type HmacSha256 = Hmac<sha2::Sha256>;

                let mut mac = HmacSha256::new_from_slice(key.as_bytes())
                    .map_err(|e| mlua::Error::RuntimeError(format!("HMAC key error: {}", e)))?;
                mac.update(msg.as_bytes());
                let result = mac.finalize().into_bytes();
                Ok(hex_encode(&result))
            })?,
        )?;

        lua.globals().set("crypto", table)?;
        Ok(())
    }

    fn register_env_module(lua: &Lua, exposed_env: &[String]) -> LuaResult<()> {
        let table = lua.create_table()?;
        let exposed_env = exposed_env.to_vec();

        table.set(
            "get",
            lua.create_function(move |_lua, name: String| {
                if !exposed_env.contains(&name) {
                    return Ok(Value::Nil);
                }
                match std::env::var(&name) {
                    Ok(val) => Ok(Value::String(_lua.create_string(&val)?)),
                    Err(_) => Ok(Value::Nil),
                }
            })?,
        )?;

        lua.globals().set("env", table)?;
        Ok(())
    }

    fn register_time_module(lua: &Lua) -> LuaResult<()> {
        let table = lua.create_table()?;

        table.set(
            "now_ms",
            lua.create_function(|_, ()| {
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as f64;
                Ok(ms)
            })?,
        )?;

        lua.globals().set("time", table)?;
        Ok(())
    }

    fn register_shared_module(lua: &Lua, shared_state: &SharedState) -> LuaResult<()> {
        let table = lua.create_table()?;

        let state = shared_state.clone();
        table.set(
            "get",
            lua.create_function(move |_, key: String| {
                let map = state.read().unwrap();
                match map.get(&key) {
                    Some(&val) => Ok(Value::Number(val)),
                    None => Ok(Value::Nil),
                }
            })?,
        )?;

        let state = shared_state.clone();
        table.set(
            "set",
            lua.create_function(move |_, (key, value): (String, f64)| {
                let mut map = state.write().unwrap();
                map.insert(key, value);
                Ok(())
            })?,
        )?;

        let state = shared_state.clone();
        table.set(
            "incr",
            lua.create_function(move |_, key: String| {
                let mut map = state.write().unwrap();
                let val = map.entry(key).or_insert(0.0);
                *val += 1.0;
                Ok(*val)
            })?,
        )?;

        lua.globals().set("shared", table)?;
        Ok(())
    }

    /// Lock a state from `pool` for one hook call.
    ///
    /// Starts at a round-robin index but takes the first state that is free:
    /// hooks run synchronously on the async workers, so blocking on a state
    /// another worker holds would stall every connection on this worker for
    /// the length of someone else's hook. Only when every state is busy does
    /// it wait, on the round-robin one. A poisoned state (a panic mid-hook) is
    /// reused rather than taken out of service: `cleanup_lua_state` runs after
    /// every call, and the alternative is a pool that shrinks to nothing.
    fn acquire(pool: &StatePool) -> std::sync::MutexGuard<'_, LuaSlot> {
        use std::sync::TryLockError;
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = pool.len();
        let start = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % n;
        for i in 0..n {
            match pool[(start + i) % n].try_lock() {
                Ok(guard) => return guard,
                Err(TryLockError::Poisoned(p)) => return p.into_inner(),
                Err(TryLockError::WouldBlock) => continue,
            }
        }
        pool[start].lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Run `f` on a state from `pool`, then clear the globals it left behind
    /// — whatever `f` returned, error included. A hook that raises halfway
    /// has had as much chance to set request-scoped globals as one that
    /// returns, and those must not reach the next request served by this
    /// state.
    fn with_state<R>(pool: &StatePool, f: impl FnOnce(&Lua) -> R) -> R {
        let slot = Self::acquire(pool);
        let result = f(&slot.lua);
        Self::cleanup_lua_state(&slot);
        result
    }

    /// The route script `name`, if it is loaded and defines `hook`.
    fn route_script_with(&self, name: &str, hook: Hook) -> Option<&RouteScript> {
        self.inner
            .route_scripts
            .get(name)
            .filter(|r| r.hooks.has(hook))
    }

    // --- Hook accessors ---

    pub fn has_on_request(&self) -> bool {
        self.inner.hooks.on_request
    }

    pub fn has_on_route(&self) -> bool {
        self.inner.hooks.on_route
    }

    pub fn has_on_response(&self) -> bool {
        self.inner.hooks.on_response
    }

    pub fn has_on_request_end(&self) -> bool {
        self.inner.hooks.on_request_end
    }

    /// Whether the route script `name` is loaded and defines `hook`. Lets the
    /// caller skip building a request table for a script that would ignore it.
    pub fn route_has_hook(&self, name: &str, hook: Hook) -> bool {
        self.route_script_with(name, hook).is_some()
    }

    /// Whether `on_response` would run anywhere — globally or in some route
    /// script — so the proxy only keeps a copy of the request when it will.
    pub fn may_run_on_response(&self) -> bool {
        self.inner.hooks.on_response || self.inner.any_route_on_response
    }

    /// Same as `may_run_on_response`, for `on_request_end`.
    pub fn may_run_on_request_end(&self) -> bool {
        self.inner.hooks.on_request_end || self.inner.any_route_on_request_end
    }

    // --- Hook calls ---

    /// Call on_request(req). Returns Continue or Deny.
    pub fn call_on_request(&self, req: &mut LuaRequest) -> RequestHookResult {
        if !self.inner.hooks.on_request {
            return RequestHookResult::Continue(req.clone());
        }

        let result = Self::with_state(&self.inner.states, |lua| self.do_on_request(lua, req));
        match result {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_request error: {}", e);
                Self::script_error_deny()
            }
        }
    }

    /// Fail-closed result for a request-path hook that raised an error.
    fn script_error_deny() -> RequestHookResult {
        RequestHookResult::Deny {
            status: SCRIPT_ERROR_STATUS,
            body: SCRIPT_ERROR_BODY.to_string(),
        }
    }

    /// Call on_request for a specific route script. Returns Continue or Deny.
    pub fn call_route_on_request(
        &self,
        script_name: &str,
        req: &mut LuaRequest,
    ) -> RequestHookResult {
        let Some(script) = self.route_script_with(script_name, Hook::Request) else {
            return RequestHookResult::Continue(req.clone());
        };

        let result = Self::with_state(&script.states, |lua| self.do_on_request(lua, req));
        match result {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_request error in {}: {}", script_name, e);
                Self::script_error_deny()
            }
        }
    }

    /// Remove script-defined globals after each hook call to prevent cross-request leakage.
    /// Preserves everything present at state-creation time (built-in modules, the loaded
    /// stdlib, base library functions, and hook functions) via the baseline snapshot taken
    /// in `create_lua_state`; only globals a script created at request time are cleared.
    ///
    /// Runs after every hook call, so it is kept cheap: one raw lookup per global
    /// against the baseline, keyed by the global's own key value — no string
    /// conversion, and no allocation unless a stray global actually exists.
    fn cleanup_lua_state(slot: &LuaSlot) {
        let globals = slot.lua.globals();
        let mut stray: Vec<Value> = Vec::new();
        for pair in globals.pairs::<Value, Value>() {
            let Ok((key, _)) = pair else {
                break;
            };
            let known = slot
                .baseline
                .raw_get::<Value>(key.clone())
                .map(|v| !v.is_nil())
                .unwrap_or(false);
            if !known {
                stray.push(key);
            }
        }
        for key in stray {
            let _ = globals.raw_set(key, Value::Nil);
        }
    }

    fn do_on_request(&self, lua: &Lua, req: &mut LuaRequest) -> LuaResult<RequestHookResult> {
        let func: Function = lua.globals().get("on_request")?;

        // Build the request table
        let req_table = self.lua_request_table(lua, req)?;

        Self::arm_hook_timeout(lua, self.inner.hook_timeout);
        let result: Value = func.call(req_table.clone())?;

        match result {
            Value::Nil => {
                // No return value — read back any modified headers
                self.read_back_request(lua, &req_table, req)?;
                Ok(RequestHookResult::Continue(req.clone()))
            }
            Value::Table(t) => {
                // Check if it's a deny response: { status = N, body = "..." }
                if let Ok(status) = t.get::<u16>("status") {
                    let body: String = t.get::<String>("body").unwrap_or_default();
                    Ok(RequestHookResult::Deny { status, body })
                } else {
                    self.read_back_request(lua, &req_table, req)?;
                    Ok(RequestHookResult::Continue(req.clone()))
                }
            }
            _ => {
                self.read_back_request(lua, &req_table, req)?;
                Ok(RequestHookResult::Continue(req.clone()))
            }
        }
    }

    /// Call on_route(req, matched_target). Returns Override(url) or Default.
    pub fn call_on_route(&self, req: &LuaRequest, matched_target: &str) -> RouteHookResult {
        if !self.inner.hooks.on_route {
            return RouteHookResult::Default;
        }

        let result = Self::with_state(&self.inner.states, |lua| {
            self.do_on_route(lua, req, matched_target)
        });
        match result {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_route error: {}", e);
                Self::route_script_error_deny()
            }
        }
    }

    /// Fail-closed result for an on_route hook that raised an error.
    fn route_script_error_deny() -> RouteHookResult {
        RouteHookResult::Deny {
            status: SCRIPT_ERROR_STATUS,
            body: SCRIPT_ERROR_BODY.to_string(),
        }
    }

    /// Call on_route for a specific route script.
    pub fn call_route_on_route(
        &self,
        script_name: &str,
        req: &LuaRequest,
        matched_target: &str,
    ) -> RouteHookResult {
        let Some(script) = self.route_script_with(script_name, Hook::Route) else {
            return RouteHookResult::Default;
        };

        let result = Self::with_state(&script.states, |lua| {
            self.do_on_route(lua, req, matched_target)
        });
        match result {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_route error in {}: {}", script_name, e);
                Self::route_script_error_deny()
            }
        }
    }

    fn do_on_route(
        &self,
        lua: &Lua,
        req: &LuaRequest,
        matched_target: &str,
    ) -> LuaResult<RouteHookResult> {
        let func: Function = lua.globals().get("on_route")?;
        let req_table = self.lua_request_table(lua, req)?;

        Self::arm_hook_timeout(lua, self.inner.hook_timeout);
        let result: Value = func.call((req_table, matched_target.to_string()))?;

        match result {
            Value::String(s) => Ok(RouteHookResult::Override(s.to_str()?.to_string())),
            _ => Ok(RouteHookResult::Default),
        }
    }

    /// Call on_response(req, resp). Returns ResponseMod with any changes.
    pub fn call_on_response(
        &self,
        req: &LuaRequest,
        status: u16,
        headers: &HashMap<String, String>,
    ) -> ResponseMod {
        if !self.inner.hooks.on_response {
            return ResponseMod::default();
        }

        let result = Self::with_state(&self.inner.states, |lua| {
            self.do_on_response(lua, req, status, headers)
        });
        match result {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_response error: {}", e);
                ResponseMod::default()
            }
        }
    }

    /// Call on_response for a specific route script.
    pub fn call_route_on_response(
        &self,
        script_name: &str,
        req: &LuaRequest,
        status: u16,
        headers: &HashMap<String, String>,
    ) -> ResponseMod {
        let Some(script) = self.route_script_with(script_name, Hook::Response) else {
            return ResponseMod::default();
        };

        let result = Self::with_state(&script.states, |lua| {
            self.do_on_response(lua, req, status, headers)
        });
        match result {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_response error in {}: {}", script_name, e);
                ResponseMod::default()
            }
        }
    }

    fn do_on_response(
        &self,
        lua: &Lua,
        req: &LuaRequest,
        status: u16,
        headers: &HashMap<String, String>,
    ) -> LuaResult<ResponseMod> {
        let func: Function = lua.globals().get("on_response")?;

        let req_table = self.lua_request_table(lua, req)?;

        // Build response table
        let resp_table = lua.create_table()?;
        resp_table.set("status", status)?;

        let headers_table = lua.create_table()?;
        for (k, v) in headers {
            headers_table.set(k.as_str(), v.as_str())?;
        }
        resp_table.set("headers", headers_table)?;

        // Track modifications via metatables with __newindex
        let set_headers_table = lua.create_table()?;
        let remove_headers_table = lua.create_table()?;
        let mods_table = lua.create_table()?;
        mods_table.set("set_headers", set_headers_table)?;
        mods_table.set("remove_headers", remove_headers_table)?;
        mods_table.set("replace_body", Value::Nil)?;
        mods_table.set("override_status", Value::Nil)?;

        // Provide helper methods on resp_table (accept self for resp:method() syntax)
        let mods_ref = mods_table.clone();
        resp_table.set(
            "set_header",
            lua.create_function(
                move |_lua, (_self_table, name, value): (Table, String, String)| {
                    let sh: Table = mods_ref.get("set_headers")?;
                    sh.set(name, value)?;
                    Ok(())
                },
            )?,
        )?;

        let mods_ref = mods_table.clone();
        resp_table.set(
            "remove_header",
            lua.create_function(move |_lua, (_self_table, name): (Table, String)| {
                let rh: Table = mods_ref.get("remove_headers")?;
                let len = rh.len()? + 1;
                rh.set(len, name)?;
                Ok(())
            })?,
        )?;

        let mods_ref = mods_table.clone();
        resp_table.set(
            "replace_body",
            lua.create_function(move |_lua, (_self_table, body): (Table, String)| {
                mods_ref.set("replace_body", body)?;
                Ok(())
            })?,
        )?;

        let mods_ref = mods_table.clone();
        resp_table.set(
            "set_status",
            lua.create_function(move |_lua, (_self_table, code): (Table, u16)| {
                mods_ref.set("override_status", code)?;
                Ok(())
            })?,
        )?;

        Self::arm_hook_timeout(lua, self.inner.hook_timeout);
        let _result: Value = func.call((req_table, resp_table))?;

        // Read back modifications
        let mut mods = ResponseMod::default();

        let sh: Table = mods_table.get("set_headers")?;
        for pair in sh.pairs::<String, String>() {
            let (k, v) = pair?;
            mods.set_headers.insert(k, v);
        }

        let rh: Table = mods_table.get("remove_headers")?;
        for pair in rh.pairs::<i64, String>() {
            let (_, v) = pair?;
            mods.remove_headers.push(v);
        }

        if let Ok(body) = mods_table.get::<String>("replace_body") {
            mods.replace_body = Some(body);
        }

        if let Ok(status) = mods_table.get::<u16>("override_status") {
            mods.override_status = Some(status);
        }

        Ok(mods)
    }

    /// Call on_request_end(req, resp_status, duration_ms).
    pub fn call_on_request_end(
        &self,
        req: &LuaRequest,
        status: u16,
        duration_ms: f64,
        target: &str,
    ) {
        if !self.inner.hooks.on_request_end {
            return;
        }

        let result = Self::with_state(&self.inner.states, |lua| {
            self.do_on_request_end(lua, req, status, duration_ms, target)
        });
        if let Err(e) = result {
            tracing::error!("Lua on_request_end error: {}", e);
        }
    }

    /// Call on_request_end for a specific route script.
    pub fn call_route_on_request_end(
        &self,
        script_name: &str,
        req: &LuaRequest,
        status: u16,
        duration_ms: f64,
        target: &str,
    ) {
        let Some(script) = self.route_script_with(script_name, Hook::RequestEnd) else {
            return;
        };

        let result = Self::with_state(&script.states, |lua| {
            self.do_on_request_end(lua, req, status, duration_ms, target)
        });
        if let Err(e) = result {
            tracing::error!("Lua on_request_end error in {}: {}", script_name, e);
        }
    }

    fn do_on_request_end(
        &self,
        lua: &Lua,
        req: &LuaRequest,
        status: u16,
        duration_ms: f64,
        target: &str,
    ) -> LuaResult<()> {
        let func: Function = lua.globals().get("on_request_end")?;
        let req_table = self.lua_request_table(lua, req)?;

        let resp_table = lua.create_table()?;
        resp_table.set("status", status)?;

        Self::arm_hook_timeout(lua, self.inner.hook_timeout);
        func.call::<()>((req_table, resp_table, duration_ms, target.to_string()))?;

        Ok(())
    }

    /// Check if a route script is loaded.
    pub fn has_route_script(&self, name: &str) -> bool {
        self.inner.route_scripts.contains_key(name)
    }

    // --- Helpers ---

    fn lua_request_table(&self, lua: &Lua, req: &LuaRequest) -> LuaResult<Table> {
        let table = lua.create_table()?;
        table.set("method", req.method.as_str())?;
        table.set("path", req.path.as_str())?;
        table.set("host", req.host.as_str())?;
        table.set("content_length", req.content_length)?;

        let headers_table = lua.create_table()?;
        for (k, v) in &req.headers {
            headers_table.set(k.as_str(), v.as_str())?;
        }
        let headers_ref = headers_table.clone();
        let headers_ref2 = headers_table.clone();
        table.set("headers", headers_table)?;

        // Helper method: req:header("Name")
        table.set(
            "header",
            lua.create_function(move |_lua, (_self_table, name): (Table, String)| {
                let val: Value = headers_ref.get(name.to_lowercase().as_str())?;
                Ok(val)
            })?,
        )?;

        // Helper method: req:set_header("Name", "Value")
        table.set(
            "set_header",
            lua.create_function(
                move |_lua, (_self_table, name, value): (Table, String, String)| {
                    headers_ref2.set(name.to_lowercase().as_str(), value.as_str())?;
                    Ok(())
                },
            )?,
        )?;

        // Helper method: req:deny(status, body)
        table.set(
            "deny",
            lua.create_function(|lua, (_self_table, status, body): (Table, u16, String)| {
                let t = lua.create_table()?;
                t.set("status", status)?;
                t.set("body", body)?;
                Ok(t)
            })?,
        )?;

        Ok(table)
    }

    fn read_back_request(
        &self,
        _lua: &Lua,
        req_table: &Table,
        req: &mut LuaRequest,
    ) -> LuaResult<()> {
        // Read back modified headers
        if let Ok(headers_table) = req_table.get::<Table>("headers") {
            let mut new_headers = HashMap::new();
            for pair in headers_table.pairs::<String, String>() {
                let (k, v) = pair?;
                new_headers.insert(k, v);
            }
            req.headers = new_headers;
        }

        // Read back modified path
        if let Ok(path) = req_table.get::<String>("path") {
            req.path = path;
        }

        Ok(())
    }
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Configuration for the scripting engine.
#[derive(Clone, Debug)]
pub struct ScriptingConfig {
    pub enabled: bool,
    pub scripts_dir: PathBuf,
    pub hook_timeout_ms: u64,
}

impl Default for ScriptingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scripts_dir: PathBuf::from("./scripts/lua"),
            hook_timeout_ms: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> LuaRequest {
        LuaRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: HashMap::new(),
            host: "h".into(),
            content_length: 0,
        }
    }

    fn engine_with(src: &str) -> (tempfile::TempDir, LuaEngine) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.lua"), src).unwrap();
        let engine = LuaEngine::new(dir.path(), 1, Duration::from_millis(100), &[]).unwrap();
        (dir, engine)
    }

    /// Reads the global `leaked` through on_request: "nil" when the previous
    /// hook's request-scoped global was cleaned up.
    const PROBE: &str = r#"
        function on_request(req)
            req:set_header("x-leaked", tostring(leaked))
        end
    "#;

    fn probe(engine: &LuaEngine) -> String {
        let mut r = req();
        match engine.call_on_request(&mut r) {
            RequestHookResult::Continue(r) => r.headers["x-leaked"].clone(),
            RequestHookResult::Deny { status, body } => panic!("denied {status} {body}"),
        }
    }

    #[test]
    fn globals_do_not_leak_from_a_failing_on_route() {
        let (_dir, engine) = engine_with(&format!(
            "{PROBE}\nfunction on_route(req, target) leaked = 'secret'; error('boom') end"
        ));
        assert!(matches!(
            engine.call_on_route(&req(), "http://t"),
            RouteHookResult::Deny { .. }
        ));
        assert_eq!(probe(&engine), "nil");
    }

    #[test]
    fn globals_do_not_leak_from_on_request_end() {
        let (_dir, engine) = engine_with(&format!(
            "{PROBE}\nfunction on_request_end(req, resp, ms, target) leaked = 'secret' end"
        ));
        engine.call_on_request_end(&req(), 200, 1.0, "http://t");
        assert_eq!(probe(&engine), "nil");
    }

    #[test]
    fn globals_do_not_leak_from_a_failing_on_response() {
        let (_dir, engine) = engine_with(&format!(
            "{PROBE}\nfunction on_response(req, resp) leaked = 'secret'; error('boom') end"
        ));
        let _ = engine.call_on_response(&req(), 200, &HashMap::new());
        assert_eq!(probe(&engine), "nil");
    }

    #[test]
    fn load_time_globals_and_stdlib_survive_cleanup() {
        let (_dir, engine) = engine_with(
            r#"
            config_value = "kept"
            function on_request(req)
                req:set_header("x-v", config_value .. math.floor(1.5))
            end
            "#,
        );
        for _ in 0..3 {
            let mut r = req();
            match engine.call_on_request(&mut r) {
                RequestHookResult::Continue(r) => assert_eq!(r.headers["x-v"], "kept1"),
                RequestHookResult::Deny { body, .. } => panic!("{body}"),
            }
        }
    }

    #[test]
    fn route_hook_presence_is_known_without_running_the_script() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("r.lua"),
            "function on_route(req, t) return nil end",
        )
        .unwrap();
        let engine = LuaEngine::with_route_scripts(
            dir.path(),
            1,
            Duration::from_millis(100),
            &[],
            &["r.lua".to_string()],
            &[],
        )
        .unwrap();
        assert!(engine.route_has_hook("r.lua", Hook::Route));
        assert!(!engine.route_has_hook("r.lua", Hook::Request));
        assert!(!engine.route_has_hook("missing.lua", Hook::Route));
        assert!(!engine.may_run_on_response());
        assert!(!engine.may_run_on_request_end());
    }

    #[test]
    fn a_busy_state_is_skipped_for_a_free_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.lua"), PROBE).unwrap();
        let engine = LuaEngine::new(dir.path(), 2, Duration::from_millis(100), &[]).unwrap();
        // Hold one state; every call must still get the other without waiting.
        let _held = engine.inner.states[0].lock().unwrap();
        for _ in 0..4 {
            assert_eq!(probe(&engine), "nil");
        }
    }
}
