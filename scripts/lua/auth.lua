-- auth.lua
-- Basic auth: validate Authorization header using built-in modules.
-- Assign to routes via @script:auth.lua in proxy.conf.
--
-- Credentials are read from environment variables:
--   AUTH_PASS_<USERNAME> = sha256 hash of the password
--
-- Example:
--   export AUTH_PASS_ADMIN=$(echo -n "secret" | sha256sum | cut -d' ' -f1)

function on_request(req)
    local auth = req:header("authorization")
    if not auth then
        return req:deny(401, "Unauthorized")
    end

    local scheme, encoded = auth:match("^(%w+)%s+(.+)$")
    if scheme ~= "Basic" then
        return req:deny(401, "Unsupported auth scheme")
    end

    local decoded = base64.decode(encoded)
    local user, pass = decoded:match("^([^:]+):(.+)$")
    if not user or not pass then
        return req:deny(401, "Malformed credentials")
    end

    local expected_hash = env.get("AUTH_PASS_" .. user:upper())
    if not expected_hash or crypto.sha256(pass) ~= expected_hash then
        return req:deny(403, "Invalid credentials")
    end

    req:set_header("x-user", user)
    log.info("Authenticated user: " .. user)
end
