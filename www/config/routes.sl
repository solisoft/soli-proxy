// Soli Proxy Website Routes

get("/", "home#index");
get("/docs", "docs#getting_started");
get("/docs/getting-started", "docs#getting_started");
get("/docs/apps", "docs#apps");
get("/docs/configuration", "docs#configuration");
get("/docs/dev-https", "docs#dev_https");
get("/docs/admin-api", "docs#admin_api");
get("/docs/scripting", "docs#scripting");
get("/docs/security", "docs#security");
get("/docs/deployment", "docs#deployment");
get("/docs/benchmark", "docs#benchmark");
get("/health", "home#health");
get("/up", "home#up");
