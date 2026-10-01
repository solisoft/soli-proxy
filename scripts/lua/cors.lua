-- cors.lua
-- CORS for an allowlist of origins, including preflight requests.
-- Attach globally or per route in proxy.conf:
--   [global] @script:cors.lua
--   /api/* -> http://localhost:3000  @script:cors.lua
--
-- Only origins listed below get CORS headers; any other origin gets none, so
-- the browser keeps enforcing the same-origin policy for it. Do not replace
-- the allowlist with "*" while ALLOW_CREDENTIALS is true: browsers refuse
-- that combination, and reflecting every Origin back would hand cookies-bearing
-- cross-site access to any page on the internet.

local ALLOWED_ORIGINS = {
    ["https://app.example.com"] = true,
    ["http://localhost:5173"] = true,
}
local ALLOW_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
local ALLOW_HEADERS = "Content-Type, Authorization, X-Requested-With"
local ALLOW_CREDENTIALS = true
local MAX_AGE_SECS = "600"

-- A preflight is an OPTIONS request carrying Access-Control-Request-Method.
-- It is answered here, in on_response, rather than denied in on_request:
-- a deny() response cannot carry headers, and a preflight answer without
-- Access-Control-Allow-* is a failed preflight. Whatever the backend said
-- to the OPTIONS request (often 404 or 405), the client gets a 204.
local function is_preflight(req)
    return req.method == "OPTIONS" and req:header("access-control-request-method") ~= nil
end

function on_response(req, resp)
    local origin = req:header("origin")
    if origin == nil or not ALLOWED_ORIGINS[origin] then
        return
    end

    resp:set_header("Access-Control-Allow-Origin", origin)
    -- The answer depends on Origin: caches must not reuse it for another one.
    resp:set_header("Vary", "Origin")
    if ALLOW_CREDENTIALS then
        resp:set_header("Access-Control-Allow-Credentials", "true")
    end

    if is_preflight(req) then
        resp:set_header("Access-Control-Allow-Methods", ALLOW_METHODS)
        resp:set_header("Access-Control-Allow-Headers", ALLOW_HEADERS)
        resp:set_header("Access-Control-Max-Age", MAX_AGE_SECS)
        resp:set_status(204)
        resp:replace_body("")
    end
end
