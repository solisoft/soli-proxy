// Admin UI Routes

// Dashboard
get("/", "home#index");

// Routes management
get("/routes", "routes#index");

// Apps management
get("/apps", "apps#index");

// Metrics
get("/metrics", "metrics#index");

// Configuration viewer
get("/config", "config#index");

// Circuit breaker
get("/circuit-breaker", "circuit_breaker#index");

// Health check
get("/health", "home#health");

print("Admin routes loaded!");
