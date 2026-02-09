-- example_routing.lua
-- Demonstrates the on_route hook for dynamic routing decisions.
-- Rename to routing.lua and enable scripting in config.toml to activate.

function on_route(req, matched_target)
    -- A/B testing: send 10% of traffic to canary backend
    if math.random(100) <= 10 then
        return "http://127.0.0.1:3001" .. req.path
    end

    -- Route by custom header (API versioning)
    local version = req:header("x-api-version")
    if version == "v2" then
        return "http://127.0.0.1:3002" .. req.path
    end

    -- Return nil to use the default matched target
    return nil
end
