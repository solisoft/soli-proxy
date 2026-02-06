#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${1:-localhost:8008}"
DURATION="${2:-5s}"
CONNECTIONS="${3:-100}"

echo "=========================================="
echo "Soli Proxy Benchmark"
echo "=========================================="
echo "Target: $HOST"
echo "Duration: $DURATION"
echo "Connections: $CONNECTIONS"
echo "=========================================="

if ! command -v hey &> /dev/null; then
    echo "Error: 'hey' not found. Install from: https://github.com/rakyll/hey"
    echo "Or: go install github.com/rakyll/hey@latest"
    exit 1
fi

echo ""
echo "Running benchmark..."
echo ""

hey -host "example.com" -n 10000 -c "$CONNECTIONS" -d "$DURATION" "$HOST"

echo ""
echo "=========================================="
echo "Benchmark complete!"
echo "=========================================="
