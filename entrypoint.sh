#!/bin/bash
set -e

# Run Node.js script (writes directly to /harness/secrets/ files; no stdout — safe even if entrypoint is bypassed)
node /app/src/index.js

# Hand over control to the Docker command (if any)
exec "$@"
