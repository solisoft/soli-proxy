-- example_response.lua
-- Demonstrates the on_response hook for response transformation.
-- Rename to response.lua and enable scripting in config.toml to activate.

function on_response(req, resp)
    -- Inject CORS headers
    resp:set_header("Access-Control-Allow-Origin", "*")
    resp:set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

    -- Remove server fingerprint headers
    resp:remove_header("Server")
    resp:remove_header("X-Powered-By")

    -- Custom error pages
    if resp.status == 502 then
        resp:set_status(503)
        resp:replace_body("Service temporarily unavailable. Please try again later.")
    end
end
