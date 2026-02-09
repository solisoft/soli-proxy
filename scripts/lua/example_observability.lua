-- example_observability.lua
-- Demonstrates the on_request_end hook for custom logging and metrics.
-- Rename to observability.lua and enable scripting in config.toml to activate.

function on_request_end(req, resp, duration_ms, target)
    -- Log slow requests
    if duration_ms > 100 then
        log.warn(string.format(
            "Slow request: %s %s -> %s (%.1fms, status %d)",
            req.method, req.path, target, duration_ms, resp.status
        ))
    end

    -- Log server errors
    if resp.status >= 500 then
        log.error(string.format(
            "Server error: %s %s -> status %d (%.1fms)",
            req.method, req.path, resp.status, duration_ms
        ))
    end
end
