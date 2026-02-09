-- rate_limit.lua
-- Token bucket rate limiter using the shared state module.
-- Assign to routes via @script:rate_limit.lua in proxy.conf.
--
-- Limits requests per client IP (from x-forwarded-for or host) per time window.

local RATE_LIMIT = 100       -- requests per window
local WINDOW_MS  = 60000     -- 1 minute

function on_request(req)
    local client = req:header("x-forwarded-for") or req.host
    local window = math.floor(time.now_ms() / WINDOW_MS)
    local key = "rl:" .. client .. ":" .. window

    local count = shared.incr(key)
    if count > RATE_LIMIT then
        log.warn("Rate limit exceeded for " .. client)
        return req:deny(429, "Too Many Requests")
    end
end
