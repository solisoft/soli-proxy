-- logging.lua
-- One log line per completed request, through the proxy's own logger (so it
-- follows [logging] format/output in config.toml, under target "lua").
-- Attach globally in proxy.conf:
--   [global] @script:logging.lua
--
-- `[logging] log_endpoints = true` already logs every request natively, with
-- no Lua cost; use this script when you want a different shape or a filter,
-- e.g. only slow or failed requests (set SLOW_MS / ONLY_ERRORS below).

local SLOW_MS = 0          -- log only requests slower than this (0 = all)
local ONLY_ERRORS = false  -- log only 4xx/5xx responses

function on_request_end(req, resp, duration_ms, target)
    if duration_ms < SLOW_MS then
        return
    end
    if ONLY_ERRORS and resp.status < 400 then
        return
    end

    local line = string.format(
        "%s %s%s -> %s %d %.1fms",
        req.method, req.host, req.path, target, resp.status, duration_ms
    )
    if resp.status >= 500 then
        log.error(line)
    elseif resp.status >= 400 then
        log.warn(line)
    else
        log.info(line)
    end
end
