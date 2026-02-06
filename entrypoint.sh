#!/bin/bash

# 1. Create a temporary file to store the secrets
# Using mktemp ensures the file name is unique and not guessable
SECRETS_FILE=$(mktemp)

# 2. Run the Node.js plugin
# Redirect STDOUT (secrets) to our file, and let STDERR (logs) flow to the console
node /app/src/index.js > "$SECRETS_FILE"

# 3. Securely process the secrets
# SECURITY NOTE: All secrets are written to /harness/outputs/ and /harness/secrets/
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
    printf "%s=%s\n" "$name" "$value" >> /harness/outputs/outputs.txt
    
    # For environment variables, also write to env_vars.txt for Harness to pick up
    # These are available as output variables and can be referenced in envVariables section
    if [ "$type" = "env" ]; then
        printf "%s=%s\n" "$name" "$value" >> /harness/outputs/env_vars.txt
    fi
    
    # Write to file for direct access (bypasses Harness truncation)
    echo -n "$value" > "/harness/secrets/${name}"
    chmod 600 "/harness/secrets/${name}"  # Restrict permissions to owner only
    
done < "$SECRETS_FILE"

# 4. Secure Clean up
rm -f "$SECRETS_FILE"

# 5. Hand over control to the Docker command (if any)
exec "$@"