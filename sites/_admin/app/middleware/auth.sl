// ============================================================================
// Authentication Middleware (Scope-Only)
// ============================================================================
//
// This middleware checks for authentication.
// It only runs when explicitly scoped to routes.
//
// Usage in routes.sl:
//   middleware("authenticate", -> {
//       get("/admin", "admin#index");
//       get("/admin/settings", "admin#settings");
//   });
//
// Configuration:
// - `// order: N` - Execution order (lower runs first)
// - `// scope_only: true` - Only runs when explicitly scoped
//
// ============================================================================

// order: 20
// scope_only: true

fn authenticate(req: Any) -> Any {
    let headers = req["headers"];

    // Example: Check for API key in header
    let api_key = "";
    if has_key(headers, "X-Api-Key") {
        api_key = headers["X-Api-Key"];
    } else if has_key(headers, "x-api-key") {
        api_key = headers["x-api-key"];
    }

    // TODO: Replace with your authentication logic
    // For example, verify JWT token, check session, etc.
    if api_key == "" {
        return {
            "continue": false,
            "response": {
                "status": 401,
                "headers": {"Content-Type": "application/json"},
                "body": json_stringify({
                    "error": "Unauthorized",
                    "message": "Authentication required"
                })
            }
        };
    }

    // Authentication passed, continue to handler
    return {
        "continue": true,
        "request": req
    };
}
