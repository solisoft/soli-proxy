-- example_auth.lua
-- Demonstrates the on_request hook for authentication and request validation.
-- Rename to auth.lua (or any .lua name) and enable scripting in config.toml to activate.

function on_request(req)
    -- Block requests without Authorization header
    local auth = req:header("authorization")
    if not auth then
        return req:deny(401, "Unauthorized: missing Authorization header")
    end

    -- Block suspicious user agents (basic WAF)
    local ua = req:header("user-agent")
    if ua and (ua:match("sqlmap") or ua:match("nikto")) then
        return req:deny(403, "Forbidden")
    end

    -- Payload size limit for upload routes
    if req.path:match("^/upload") and req.content_length > 10 * 1024 * 1024 then
        return req:deny(413, "Payload too large")
    end

    -- Add a custom header for downstream services
    req:set_header("x-proxy-auth", "verified")

    -- Returning nil means "continue processing"
end
