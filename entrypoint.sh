#!/bin/sh
set -e

# Start Redis in the background
redis-server --daemonize yes --loglevel notice

# Wait for Redis to be ready
until redis-cli ping >/dev/null 2>&1; do
  echo "waiting for redis..."
  sleep 1
done

echo "redis is ready"

# Start the API
exec /usr/local/bin/api
