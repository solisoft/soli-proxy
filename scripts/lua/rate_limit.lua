-- rate_limit.lua
-- Fixed-window rate limiter using the shared state module.
-- Assign to routes via @script:rate_limit.lua in proxy.conf.
--
-- Keyed on the client's address. NOT on X-Forwarded-For: hooks see the
-- request as the client sent it, and any client can put any value in that
-- header — keying on it let each request claim a fresh identity (and so a
-- fresh budget), or exhaust someone else's. `req.client_ip` is the key: the
-- client as the proxy decided it — the TCP peer, or, for a request through a
-- proxy listed in `[server] trusted_proxies`, the client that proxy names.
-- Without it, all clients of a host share one budget: coarser, not spoofable.
--
-- Behind a load balancer, list it in `trusted_proxies` (or use PROXY
-- protocol), or the TCP peer — the balancer — is everyone's client_ip.

local RATE_LIMIT = 100       -- requests per window
local WINDOW_MS  = 60000     -- 1 minute

function on_request(req)
    local client = req.client_ip or ("host:" .. req.host)
    local window = math.floor(time.now_ms() / WINDOW_MS)
    local key = "rl:" .. client .. ":" .. window

    local count = shared.incr(key)
    if count > RATE_LIMIT then
        log.warn("Rate limit exceeded for " .. client)
        return req:deny(429, "Too Many Requests")
    end
end
