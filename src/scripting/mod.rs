use mlua::{Function, Lua, Result as LuaResult, Table, Value};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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

/// Result of calling on_route — either override or keep default.
#[derive(Debug)]
pub enum RouteHookResult {
    Override(String),
    Default,
}

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
    states: Vec<std::sync::Mutex<Lua>>,
    has_on_request: bool,
    has_on_route: bool,
    has_on_response: bool,
    has_on_request_end: bool,
    _hook_timeout: Duration,
    /// Per-script hook pool (script_name -> per-worker Lua states)
    route_scripts: HashMap<String, Vec<std::sync::Mutex<Lua>>>,
    /// Shared state for cross-worker counters (kept alive via Arc)
    _shared_state: SharedState,
}

impl LuaEngine {
    /// Create a new LuaEngine by loading all .lua files from `scripts_dir`.
    ///
    /// `num_states` should match the number of worker threads.
    /// `hook_timeout` is the max execution time per hook call.
    pub fn new(
        scripts_dir: &Path,
        num_states: usize,
        hook_timeout: Duration,
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
        let probe_lua = Self::create_lua_state(&script_sources, hook_timeout, &shared_state)?;
        let has_on_request = probe_lua.globals().get::<Function>("on_request").is_ok();
        let has_on_route = probe_lua.globals().get::<Function>("on_route").is_ok();
        let has_on_response = probe_lua.globals().get::<Function>("on_response").is_ok();
        let has_on_request_end = probe_lua
            .globals()
            .get::<Function>("on_request_end")
            .is_ok();

        tracing::info!(
            "Lua hooks: on_request={}, on_route={}, on_response={}, on_request_end={}",
            has_on_request,
            has_on_route,
            has_on_response,
            has_on_request_end
        );

        // Build the pool of Lua states
        let mut states = Vec::with_capacity(num_states);
        states.push(std::sync::Mutex::new(probe_lua));
        for _ in 1..num_states {
            let lua = Self::create_lua_state(&script_sources, hook_timeout, &shared_state)?;
            states.push(std::sync::Mutex::new(lua));
        }

        Ok(Self {
            inner: Arc::new(LuaEngineInner {
                states,
                has_on_request,
                has_on_route,
                has_on_response,
                has_on_request_end,
                _hook_timeout: hook_timeout,
                route_scripts: HashMap::new(),
                _shared_state: shared_state,
            }),
        })
    }

    /// Create a LuaEngine with per-route script support.
    ///
    /// `global_scripts` — filenames loaded into the global pool (run on every request)
    /// `route_script_names` — unique filenames that need their own per-worker pools
    pub fn with_route_scripts(
        scripts_dir: &Path,
        num_states: usize,
        hook_timeout: Duration,
        global_scripts: &[String],
        route_script_names: &[String],
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
        let probe_lua = Self::create_lua_state(&global_sources, hook_timeout, &shared_state)?;
        let has_on_request = probe_lua.globals().get::<Function>("on_request").is_ok();
        let has_on_route = probe_lua.globals().get::<Function>("on_route").is_ok();
        let has_on_response = probe_lua.globals().get::<Function>("on_response").is_ok();
        let has_on_request_end = probe_lua
            .globals()
            .get::<Function>("on_request_end")
            .is_ok();

        tracing::info!(
            "Global Lua hooks: on_request={}, on_route={}, on_response={}, on_request_end={}",
            has_on_request,
            has_on_route,
            has_on_response,
            has_on_request_end
        );

        // Build global pool
        let mut states = Vec::with_capacity(num_states);
        states.push(std::sync::Mutex::new(probe_lua));
        for _ in 1..num_states {
            let lua = Self::create_lua_state(&global_sources, hook_timeout, &shared_state)?;
            states.push(std::sync::Mutex::new(lua));
        }

        // Build per-route-script pools
        let mut route_scripts: HashMap<String, Vec<std::sync::Mutex<Lua>>> = HashMap::new();
        for name in route_script_names {
            // Skip if it's already a global script (would run twice)
            if global_scripts.contains(name) {
                continue;
            }
            let path = scripts_dir.join(name);
            if !path.exists() {
                tracing::warn!("Route Lua script not found: {}", path.display());
                continue;
            }
            let source = std::fs::read_to_string(&path)?;
            tracing::info!("Loading route Lua script: {}", name);
            let script_sources = vec![(name.clone(), source)];

            let mut script_states = Vec::with_capacity(num_states);
            for _ in 0..num_states {
                let lua = Self::create_lua_state(&script_sources, hook_timeout, &shared_state)?;
                script_states.push(std::sync::Mutex::new(lua));
            }
            route_scripts.insert(name.clone(), script_states);
        }

        Ok(Self {
            inner: Arc::new(LuaEngineInner {
                states,
                has_on_request,
                has_on_route,
                has_on_response,
                has_on_request_end,
                _hook_timeout: hook_timeout,
                route_scripts,
                _shared_state: shared_state,
            }),
        })
    }

    fn create_lua_state(
        scripts: &[(String, String)],
        hook_timeout: Duration,
        shared_state: &SharedState,
    ) -> anyhow::Result<Lua> {
        let lua = Lua::new();

        // Set instruction count hook for timeout protection
        let timeout_ms = hook_timeout.as_millis() as u32;
        // ~1M instructions per ms is a rough estimate; we check every 10000 instructions
        let max_instructions = (timeout_ms as u64) * 1000;
        lua.set_hook(
            mlua::HookTriggers::new().every_nth_instruction(10000),
            move |_lua, _debug| {
                // This is a simplified timeout: we count instruction batches.
                // For a more accurate timeout, we'd track wall-clock time.
                static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count > 0 && count.is_multiple_of(max_instructions) {
                    // Reset for next call
                    COUNTER.store(0, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(mlua::VmState::Continue)
            },
        );

        // Register built-in modules
        Self::register_log_module(&lua)?;
        Self::register_base64_module(&lua)?;
        Self::register_crypto_module(&lua)?;
        Self::register_env_module(&lua)?;
        Self::register_time_module(&lua)?;
        Self::register_shared_module(&lua, shared_state)?;

        // Load all scripts in order
        for (name, source) in scripts {
            lua.load(source)
                .set_name(name)
                .exec()
                .map_err(|e| anyhow::anyhow!("Error loading Lua script '{}': {}", name, e))?;
        }

        Ok(lua)
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

        table.set(
            "decode",
            lua.create_function(|_, s: String| {
                match base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) {
                    Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
                    Err(e) => Err(mlua::Error::RuntimeError(format!(
                        "base64 decode error: {}",
                        e
                    ))),
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

    fn register_env_module(lua: &Lua) -> LuaResult<()> {
        let table = lua.create_table()?;

        table.set(
            "get",
            lua.create_function(|lua, name: String| match std::env::var(&name) {
                Ok(val) => Ok(Value::String(lua.create_string(&val)?)),
                Err(_) => Ok(Value::Nil),
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

    /// Get a Lua state from the pool, using a simple round-robin.
    /// This uses a global counter to distribute across states.
    fn get_state_index(&self) -> usize {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let idx = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        idx % self.inner.states.len()
    }

    // --- Hook accessors ---

    pub fn has_on_request(&self) -> bool {
        self.inner.has_on_request
    }

    pub fn has_on_route(&self) -> bool {
        self.inner.has_on_route
    }

    pub fn has_on_response(&self) -> bool {
        self.inner.has_on_response
    }

    pub fn has_on_request_end(&self) -> bool {
        self.inner.has_on_request_end
    }

    /// Check if a named route script has a specific hook.
    fn route_script_has_hook(lua: &Lua, hook_name: &str) -> bool {
        lua.globals().get::<Function>(hook_name).is_ok()
    }

    // --- Hook calls ---

    /// Call on_request(req). Returns Continue or Deny.
    pub fn call_on_request(&self, req: &mut LuaRequest) -> RequestHookResult {
        if !self.inner.has_on_request {
            return RequestHookResult::Continue(req.clone());
        }

        let idx = self.get_state_index();
        let lua = self.inner.states[idx].lock().unwrap();

        match self.do_on_request(&lua, req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_request error: {}", e);
                // On error, continue with unmodified request
                RequestHookResult::Continue(req.clone())
            }
        }
    }

    /// Call on_request for a specific route script. Returns Continue or Deny.
    pub fn call_route_on_request(
        &self,
        script_name: &str,
        req: &mut LuaRequest,
    ) -> RequestHookResult {
        let Some(script_states) = self.inner.route_scripts.get(script_name) else {
            return RequestHookResult::Continue(req.clone());
        };

        let idx = self.get_state_index() % script_states.len();
        let lua = script_states[idx].lock().unwrap();

        if !Self::route_script_has_hook(&lua, "on_request") {
            return RequestHookResult::Continue(req.clone());
        }

        match self.do_on_request(&lua, req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_request error in {}: {}", script_name, e);
                RequestHookResult::Continue(req.clone())
            }
        }
    }

    fn do_on_request(&self, lua: &Lua, req: &mut LuaRequest) -> LuaResult<RequestHookResult> {
        let func: Function = lua.globals().get("on_request")?;

        // Build the request table
        let req_table = self.lua_request_table(lua, req)?;

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
        if !self.inner.has_on_route {
            return RouteHookResult::Default;
        }

        let idx = self.get_state_index();
        let lua = self.inner.states[idx].lock().unwrap();

        match self.do_on_route(&lua, req, matched_target) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_route error: {}", e);
                RouteHookResult::Default
            }
        }
    }

    /// Call on_route for a specific route script.
    pub fn call_route_on_route(
        &self,
        script_name: &str,
        req: &LuaRequest,
        matched_target: &str,
    ) -> RouteHookResult {
        let Some(script_states) = self.inner.route_scripts.get(script_name) else {
            return RouteHookResult::Default;
        };

        let idx = self.get_state_index() % script_states.len();
        let lua = script_states[idx].lock().unwrap();

        if !Self::route_script_has_hook(&lua, "on_route") {
            return RouteHookResult::Default;
        }

        match self.do_on_route(&lua, req, matched_target) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Lua on_route error in {}: {}", script_name, e);
                RouteHookResult::Default
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
        if !self.inner.has_on_response {
            return ResponseMod::default();
        }

        let idx = self.get_state_index();
        let lua = self.inner.states[idx].lock().unwrap();

        match self.do_on_response(&lua, req, status, headers) {
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
        let Some(script_states) = self.inner.route_scripts.get(script_name) else {
            return ResponseMod::default();
        };

        let idx = self.get_state_index() % script_states.len();
        let lua = script_states[idx].lock().unwrap();

        if !Self::route_script_has_hook(&lua, "on_response") {
            return ResponseMod::default();
        }

        match self.do_on_response(&lua, req, status, headers) {
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
        if !self.inner.has_on_request_end {
            return;
        }

        let idx = self.get_state_index();
        let lua = self.inner.states[idx].lock().unwrap();

        if let Err(e) = self.do_on_request_end(&lua, req, status, duration_ms, target) {
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
        let Some(script_states) = self.inner.route_scripts.get(script_name) else {
            return;
        };

        let idx = self.get_state_index() % script_states.len();
        let lua = script_states[idx].lock().unwrap();

        if !Self::route_script_has_hook(&lua, "on_request_end") {
            return;
        }

        if let Err(e) = self.do_on_request_end(&lua, req, status, duration_ms, target) {
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
