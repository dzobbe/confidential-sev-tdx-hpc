#!/bin/bash
# Start SEV TEE Server

export TEE_TYPE=SEV
export PORT=${PORT:-8080}
export SERVER_ID=sev-node-$(hostname)

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "Starting SEV TEE Server..."
echo "  TEE Type: $TEE_TYPE"
echo "  Port: $PORT"
echo "  Server ID: $SERVER_ID"

python -m src.server.tee_server
