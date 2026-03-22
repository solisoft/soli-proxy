#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="${SOLI_PID_DIR:-.}"
HEALTH_PATH="${SOLI_HEALTH_PATH:-/up}"
ADMIN_PORT="${SOLI_ADMIN_PORT:-9090}"
API_KEY="${SOLI_API_KEY:-}"

PID_FILE="$PID_DIR/proxy.pid"
ADMIN_BIND="127.0.0.1"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

check_proxy_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE" 2>/dev/null)
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

restart_proxy() {
    log "soli-proxy not running, starting it..."
    cd "$SCRIPT_DIR"
    cargo run --release -- daemon 2>&1 || ./target/release/soli-proxy daemon 2>&1 || ./target/debug/soli-proxy daemon 2>&1
    sleep 3
    
    if check_proxy_running; then
        log "soli-proxy started successfully"
    else
        log "ERROR: Failed to start soli-proxy"
        exit 1
    fi
}

restart_app() {
    local app_name="$1"
    
    log "Restarting app: $app_name"
    
    response=$(curl -sf -X POST "http://${ADMIN_BIND}:${ADMIN_PORT}/api/apps/${app_name}/restart" \
        -H "Authorization: Bearer ${API_KEY}" 2>/dev/null || echo '{"error":"curl failed"}')
    
    if echo "$response" | grep -q '"error"'; then
        log "ERROR: Failed to restart $app_name: $response"
        return 1
    else
        log "App $app_name restart initiated"
        return 0
    fi
}

check_app_health() {
    local port="$1"
    local timeout_sec="${2:-3}"
    
    if curl -sf --connect-timeout "$timeout_sec" --max-time "$((timeout_sec + 2))" \
        "http://localhost:${port}${HEALTH_PATH}" > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

main() {
    log "Starting soli-proxy health check..."
    
    if ! check_proxy_running; then
        log "soli-proxy is not running"
        restart_proxy
    else
        log "soli-proxy is running (PID: $(cat "$PID_FILE"))"
    fi
    
    conf_file="./proxy.conf"
    if [ ! -f "$conf_file" ]; then
        log "ERROR: proxy.conf not found"
        exit 1
    fi
    
    log "Checking apps health via ${HEALTH_PATH}..."
    
    restart_needed=0
    
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [[ "$line" =~ ^# ]] && continue
        
        if [[ "$line" =~ ^([a-zA-Z0-9_.\-]+)\ -\>\ http://localhost:([0-9]+)/? ]]; then
            domain="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
            
            if [[ "$domain" == "_"* ]]; then
                continue
            fi
            
            if check_app_health "$port"; then
                log "OK: $domain (port $port)"
            else
                log "DOWN: $domain (port $port) - restarting..."
                app_name="$domain"
                restart_app "$app_name"
                restart_needed=1
            fi
        fi
    done < "$conf_file"
    
    if [ $restart_needed -eq 0 ]; then
        log "All apps are healthy"
    else
        log "Some apps were restarted"
    fi
}

main "$@"
