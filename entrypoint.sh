#!/bin/bash

# 1. Create a temporary file to store the secrets
# Using mktemp ensures the file name is unique and not guessable
SECRETS_FILE=$(mktemp)

# 2. Run the Node.js plugin
# Redirect STDOUT (secrets) to our file, and let STDERR (logs) flow to the console
node /app/src/index.js > "$SECRETS_FILE"

# 3. Securely process the secrets
# Parse lines in format: ENV:VAR_NAME='value', OUT:VAR_NAME='value', or VAR_NAME='value'
# 
# SECURITY NOTE: All secrets are written to /harness/outputs/ and /harness/secrets/
# These directories are mounted volumes scoped ONLY to the current pipeline execution.
# Harness CI automatically cleans up these volumes after pipeline completion.
# Secrets are NOT accessible outside the pipeline execution context.
mkdir -p /harness/outputs /harness/secrets

while IFS= read -r line; do
    # Skip empty lines
    if [ -z "$line" ]; then
        continue
    fi
    
    # Determine type: ENV:, OUT:, or default
    if [[ "$line" =~ ^ENV: ]]; then
        type="env"
        line="${line#ENV:}"
    elif [[ "$line" =~ ^OUT: ]]; then
        type="out"
        line="${line#OUT:}"
    else
        type="out"  # Default to output variable
    fi
    
    # Parse the line: split on first '=' to get name and value
    name="${line%%=*}"
    value="${line#*=}"
    
    # Remove surrounding single quotes from value if present
    if [[ "$value" =~ ^\'.*\'$ ]]; then
        value="${value#\'}"
        value="${value%\'}"
    fi
    
    # Skip if name is empty
    if [ -z "$name" ]; then
        continue
    fi

    # Export for the current shell session (plugin container only - not passed to next steps)
    export "$name=$value"
    
    # Write to Harness CI Plugin Output (for output variables)
    # These are scoped to the pipeline execution and accessible via:
    # <+step.output.outputVariables.VAR_NAME> in subsequent steps
    # Format: KEY=VALUE (one per line)
    printf "%s=%s\n" "$name" "$value" >> /harness/outputs/outputs.txt
    
    # For environment variables, also write to env_vars.txt for Harness to pick up
    # These are available as output variables and can be referenced in envVariables section
    if [ "$type" = "env" ]; then
        printf "%s=%s\n" "$name" "$value" >> /harness/outputs/env_vars.txt
    fi
    
    # Write to file for direct access (bypasses Harness truncation)
    # SECURITY: Files in /harness/secrets/ are scoped to pipeline execution only
    # Harness CI automatically cleans up these files after pipeline completion
    echo -n "$value" > "/harness/secrets/${name}"
    chmod 600 "/harness/secrets/${name}"  # Restrict permissions to owner only
    
    # Debug: Log (removed to reduce log noise)
    # value_length=${#value}
    # if [ "$type" = "env" ]; then
    #     echo "INFO: Set environment variable: $name (length: $value_length)"
    # else
    #     echo "INFO: Set output variable: $name (length: $value_length)"
    # fi
    # echo "INFO: Secret also written to /harness/secrets/${name} for direct file access"

done < "$SECRETS_FILE"

# 4. Secure Clean up
# Remove the temporary file to ensure no sensitive data remains on disk
# Note: /harness/outputs/ and /harness/secrets/ are cleaned up by Harness CI
# after pipeline execution completes - they are scoped to the pipeline only
rm -f "$SECRETS_FILE"

# 5. Hand over control to the Docker command (if any)
# This allows the container to be used as a wrapper for other commands
exec "$@"