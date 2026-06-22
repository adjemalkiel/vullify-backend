#!/bin/sh
set -e

# Start the worker in the background
echo "[start.sh] Starting worker..."
/usr/local/bin/worker &

# Start the API in the foreground (also runs DB migrations)
echo "[start.sh] Starting API..."
exec /usr/local/bin/api
