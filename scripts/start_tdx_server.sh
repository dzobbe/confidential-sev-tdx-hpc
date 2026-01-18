#!/bin/bash
# Start TDX TEE Server

export TEE_TYPE=TDX
export PORT=${PORT:-8080}
export SERVER_ID=tdx-node-$(hostname)

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "Starting TDX TEE Server..."
echo "  TEE Type: $TEE_TYPE"
echo "  Port: $PORT"
echo "  Server ID: $SERVER_ID"

python -m src.server.tee_server
