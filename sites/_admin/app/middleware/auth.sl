fn authenticate(req: Any) -> Any 
do
    let headers = req["headers"];
    let api_key = "";
    if has_key(headers, "X-Api-Key") {
        api_key = headers["X-Api-Key"];
    } elsif has_key(headers, "x-api-key") {
        api_key = headers["x-api-key"];
    }
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
    return {
        "continue": true,
        "request": req
    };
end