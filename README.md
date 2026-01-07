# Harness Keeper Security Plugin

A Harness CI/CD plugin that integrates with Keeper Security Secrets Manager (KSM) to securely fetch and inject secrets into your CI/CD pipelines at runtime.

## Overview

This plugin securely retrieves secrets from Keeper Security Secrets Manager and makes them available to subsequent steps in your Harness pipeline. The plugin implements a zero-knowledge architecture where secrets are retrieved directly from Keeper Vault at runtime and never pass through Harness systems in decrypted form.

**Key Features:**
- **Zero-Knowledge Architecture**: Secrets are retrieved directly from Keeper Vault at runtime
- **Multiple Authentication Methods**: Supports one-time access tokens (`US:...`) and full JSON config
- **Keeper Notation Support**: Query fields (`field`), custom fields (`custom_field`), and file attachments (`file`)
- **Multiple Output Formats**: Environment variables, file output, and output variables
- **Secure Storage**: Secrets written to `/harness/secrets/` with secure file permissions
- **Automatic Validation**: Validates token format and required config fields
- **Base64 Decoding**: Automatically decodes base64-encoded tokens

## Architecture

### Zero-Knowledge Design

The plugin ensures zero-knowledge security through the following design:

1. **Harness CI/CD** calls the custom Docker-based plugin
2. **Plugin authenticates** using KSM configuration stored in Harness Secrets Manager
3. **Secrets are retrieved** directly from Keeper Vault at runtime
4. **Decrypted secrets** are returned as step outputs for downstream stages
5. **No external storage**: Secrets never pass through Harness systems in decrypted form

All secret flow happens strictly between the plugin container and Keeper, while Harness provides orchestration, governance, and secure secret injection across the pipeline.

### Components

1. **`src/index.js`**: Main plugin logic
   - Token processing and validation
   - Keeper Secrets Manager integration
   - Secret fetching using Keeper Notation
   - Secret distribution

2. **`entrypoint.sh`**: Container entrypoint script
   - Executes the Node.js plugin
   - Captures and processes plugin output
   - Writes secrets to Harness directories
   - Manages security and cleanup

3. **`Example/Pipeline.yaml`**: Example Harness CI pipeline
   - Demonstrates plugin configuration
   - Shows secret consumption patterns

### Execution Flow

```
1. Container starts → entrypoint.sh executes
2. entrypoint.sh → Runs: node /app/src/index.js
3. Plugin processes:
   - Reads KSM_CONFIG from environment
   - Validates and decodes token (base64 if needed)
   - Initializes Keeper storage
   - Fetches secrets from Keeper using Keeper Notation
   - Outputs secrets to stdout (with ENV:/OUT: prefixes)
4. entrypoint.sh captures stdout:
   - Parses ENV:/OUT: prefixes
   - Writes to /harness/outputs/outputs.txt (output variables)
   - Writes to /harness/secrets/ (file-based access)
   - Sets secure permissions (chmod 600)
5. Subsequent steps access secrets via:
   - Files: /harness/secrets/VARIABLE_NAME (recommended)
```

## Prerequisites

- **Keeper Secrets Manager access** ([Quick Start Guide](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide))
- **Secrets Manager addon enabled** for your Keeper account
- **Membership in a Role** with the Secrets Manager enforcement policy enabled
- **A Keeper Secrets Manager Application** with secrets shared to it
- **An initialized Keeper Secrets Manager Configuration** (JSON or one-time token)
- **Record UID(s)** for the secrets you want to access ⚠️ **REQUIRED**
- **Harness CI/CD account** with a project set up
- **Docker** (for building the plugin image)
- **Node.js 18+** (for local development)

## Installation

### Build and Push Docker Image

Build the plugin Docker image:

```bash
docker build -t your-dockerhub-username/harness-keeper-plugin:latest .
```

Push to your container registry:

```bash
docker push your-dockerhub-username/harness-keeper-plugin:latest
```

**Note:** Replace `your-dockerhub-username` with your actual Docker Hub username or container registry path.

## Configuration

### 1. Create Keeper Access Token

#### Option A: One-Time Access Token
1. Log in to Keeper Security
2. Navigate to Secrets Manager
3. Generate a one-time access token (format: `US:xxxxx`)
4. Base64 encode (optional but recommended):
   ```bash
   echo -n "US:your-token-here" | base64
   ```

#### Option B: Full JSON Config
Create a JSON config with:
```json
{
  "hostname": "keepersecurity.com",
  "clientId": "your-client-id",
  "privateKey": "your-private-key"
}
```
Base64 encode:
```bash
echo -n '{"hostname":"...","clientId":"...","privateKey":"..."}' | base64
```

### 2. Create Harness Secret

In Harness, create a secret:
- **Type**: TEXT or FILE (both work)
- **Name**: `KSM_CONFIG` (or your preferred name)
- **Value**: Your base64-encoded token or JSON config

### 3. Configure Pipeline

**Before you begin:** You must have the Record UID(s) for the secrets you want to access. See "How to Get Record UID" section below.

```yaml
pipeline:
  name: harness_keeper_plugin
  identifier: harness_keeper_plugin
  projectIdentifier: default_project
  orgIdentifier: default
  stages:
    - stage:
        name: HkpCI
        identifier: HkpCI
        type: CI
        spec:
          cloneCodebase: false
          platform:
            os: Linux
            arch: Amd64
          runtime:
            type: Cloud
            spec: {}
          execution:
            steps:
              - step:
                  type: Plugin
                  name: Fetch_Keeper_Secrets
                  identifier: Fetch_Keeper_Secrets
                  spec:
                    image: your-dockerhub-username/harness-keeper-plugin:latest
                    settings:
                      secrets: |
                        JQPso5SMBpP29gKKGp6Enw/field/password > env:DB_PASSWORD
                        JQPso5SMBpP29gKKGp6Enw/field/login > env:DB_USERNAME
                        JQPso5SMBpP29gKKGp6Enw/custom_field/API_Key > env:API_KEY
                        JQPso5SMBpP29gKKGp6Enw/file/api.key > file:/app/config/api.key
                    envVariables:
                      KSM_CONFIG: <+secrets.getValue("KSM_CONFIG")>
              - step:
                  type: Run
                  name: Use_Keeper_Secrets
                  identifier: Use_Keeper_Secrets
                  spec:
                    image: alpine:3.20
                    shell: Sh
                    command: |
                      DB_USERNAME=$(cat /harness/secrets/DB_USERNAME)
                      DB_PASSWORD=$(cat /harness/secrets/DB_PASSWORD)
                      API_KEY=$(cat /harness/secrets/API_KEY)
                      echo "Secrets retrieved successfully"
                      # Use secrets in your build/deploy process
```

**Note:** `envVariables` is used ONLY to pass the Keeper configuration token to the plugin. The actual secrets retrieved from Keeper are stored in Harness pipeline volume storage at `/harness/secrets/`.

## Usage

### Secret Mapping Format

```
<keeper-notation> > <destination>
```

### Keeper Notation Format

The plugin supports three types of Keeper Notation queries:

1. **Standard Fields**: `<record-uid>/field/<field-type>`
   - Examples: `password`, `login`, `url`, `text`, `host`, etc.

2. **Custom Fields**: `<record-uid>/custom_field/<field-label>`
   - Examples: `API_Key`, `My Custom Field`, `Environment`, etc.

3. **File Attachments**: `<record-uid>/file/<file-name>`
   - Examples: `api.key`, `certificate.pem`, `config.json`, etc.

**Important:** The first part (e.g., `JQPso5SMBpP29gKKGp6Enw`) is the **Record UID**, the unique identifier for a specific secret record in Keeper.

### Destination Types

| Destination Prefix | Description | Output Location |
|-------------------|-------------|----------------|
| `env:VARIABLE_NAME` | Environment variable | `/harness/secrets/VARIABLE_NAME` |
| `file:/path/to/file` | File output | Specified file path |
| `VARIABLE_NAME` (default) | Output variable | `/harness/secrets/VARIABLE_NAME` |

### Examples

#### 1. Standard Field → Environment Variable
```yaml
secrets: |
  JQPso5SMBpP29gKKGp6Enw/field/password > env:DB_PASSWORD
  JQPso5SMBpP29gKKGp6Enw/field/login > env:DB_USERNAME
```
- Creates files: `/harness/secrets/DB_PASSWORD`, `/harness/secrets/DB_USERNAME`
- Access: `DB_PASSWORD=$(cat /harness/secrets/DB_PASSWORD)`

#### 2. Custom Field → Output Variable
```yaml
secrets: |
  JQPso5SMBpP29gKKGp6Enw/custom_field/API_Key > API_KEY
  JQPso5SMBpP29gKKGp6Enw/custom_field/Environment > ENV_NAME
```
- Creates files: `/harness/secrets/API_KEY`, `/harness/secrets/ENV_NAME`
- Access: `API_KEY=$(cat /harness/secrets/API_KEY)`

#### 3. File Attachment → File Path
```yaml
secrets: |
  JQPso5SMBpP29gKKGp6Enw/file/api.key > file:/app/config/api.key
  JQPso5SMBpP29gKKGp6Enw/file/certificate.pem > file:/app/ssl/cert.pem
```
- Downloads files and writes to specified paths
- Access: `cat /app/config/api.key`

#### 4. Mixed Usage
```yaml
secrets: |
  JQPso5SMBpP29gKKGp6Enw/field/password > env:DB_PASSWORD
  JQPso5SMBpP29gKKGp6Enw/custom_field/API_Key > API_KEY
  JQPso5SMBpP29gKKGp6Enw/file/config.json > file:/app/config.json
```

### How to Get Record UID

The Record UID is **mandatory** and identifies which specific secret record to retrieve. Obtain it using one of these methods:

**Method 1: From Keeper Web Vault**
1. Log in to your Keeper Vault
2. Open the secret record you want to access
3. Click on the record details/info icon
4. The Record UID is displayed in the record information (usually at the bottom)
5. Copy the Record UID (format: `JQPso5SMBpP29gKKGp6Enw`)

**Method 2: Using Keeper Commander CLI**
```bash
keeper list
# This will show all records with their UIDs
```

**Method 3: Using Keeper Secrets Manager SDK/API**
- Use the Keeper Secrets Manager SDK to list records and retrieve their UIDs
- The Record UID is returned when querying records

**Method 4: From Keeper Admin Console**
1. Navigate to Secrets Manager in Admin Console
2. View the Application and its shared records
3. Record UIDs are visible in the record list

**Note:** The one-time access token (`US:...`) or JSON config is used to **authenticate** and access Keeper, but you still need the **Record UID** to specify which secret record to retrieve.

## Accessing Secrets in Subsequent Steps

### Method 1: File-Based Access (Recommended)

The most reliable method for accessing secrets in subsequent steps:

```yaml
- step:
    type: Run
    name: Use_Secrets
    spec:
      image: alpine:3.20
      shell: Sh
      command: |
        DB_PASSWORD=$(cat /harness/secrets/DB_PASSWORD)
        DB_USERNAME=$(cat /harness/secrets/DB_USERNAME)
        API_KEY=$(cat /harness/secrets/API_KEY)
        # Use secrets in your process
        echo "Secrets loaded successfully"
        # Clean up after use (optional)
        rm -f /harness/secrets/DB_PASSWORD /harness/secrets/DB_USERNAME
```

**Benefits:**
- Most reliable method
- No truncation issues
- Works with all secret types
- Supports long values and special characters

### Method 2: Direct File Access (for file: prefix)

When using `file:` prefix, files are written directly to the specified path:

```yaml
- step:
    type: Run
    name: Use_File
    spec:
      command: |
        # File already at /app/config/api.key
        cat /app/config/api.key
```

## Secret Storage Mechanism

**Important:** This plugin uses **Harness pipeline volume storage**, not Harness environment variables.

- **Storage Location:** `/harness/secrets/` directory (Harness shared workspace volume)
- **Storage Type:** File-based storage on pipeline-scoped volume
- **Access Method:** Read files directly using `cat` or file operations
- **Scope:** Pipeline execution only - automatically cleaned up after completion
- **Permissions:** Files have `600` permissions (owner read/write only)

The `envVariables` section in the plugin step is **only** used to pass the `KSM_CONFIG` (Keeper configuration token) to the plugin. The actual secrets retrieved from Keeper are written to files in `/harness/secrets/` directory.

## Security

### Zero-Knowledge Architecture

- **Direct Retrieval**: Secrets are retrieved directly from Keeper Vault at runtime
- **No Decrypted Storage**: Secrets never pass through Harness systems in decrypted form
- **Pipeline-Scoped**: All secrets are scoped to the current pipeline execution
- **Automatic Cleanup**: Harness CI automatically cleans up `/harness/outputs/` and `/harness/secrets/` after pipeline completion
- **File Permissions**: Secrets written to `/harness/secrets/` have `600` permissions (owner read/write only)
- **No Persistence**: Secrets are not accessible outside the pipeline execution context

### Best Practices

1. **Use one-time access tokens** instead of permanent credentials when possible
2. **Base64 encode tokens** before storing in Harness secrets
3. **Clean up secret files** after use in pipeline steps
4. **Use appropriate secret scope** (project/org/account)
5. **Verify Record UIDs** before configuring pipelines

## Troubleshooting

### Token Not Found

**Error:** `KSM config is required`

**Solutions:**
- Verify the secret exists in Harness
- Check the secret scope matches your project
- Ensure the expression `<+secrets.getValue("KSM_CONFIG")>` is correct
- Verify secret name matches exactly

### Invalid Token Format

**Error:** `Invalid token format - expected US:xxxxx or JSON config`

**Solutions:**
- Verify the token starts with `US:` (for one-time tokens)
- Check if the token is base64 encoded (it will be auto-decoded)
- For JSON config, ensure it starts with `{` and has required fields: `hostname`, `clientId`, `privateKey`

### Token Already Used / Expired

**Error:** `Failed: token ... invalid/expired`

**Solutions:**
1. Generate a new token in Keeper Security
2. Base64 encode: `echo -n "US:new-token" | base64`
3. Update the Harness secret with the new token
4. Run the pipeline again

**Note:** One-time access tokens are single-use - generate a new token for each use or use JSON config for reusable credentials.

### Secret File Not Found

**Error:** `ERROR: Secret files not found` or `Value not found for notation: <record-uid>/field/<field-type>`

**Solutions:**
- **Verify Record UID is correct**: The Record UID must match exactly (case-sensitive)
- **Check Record UID exists**: Ensure the record exists in Keeper and is shared to your Secrets Manager Application
- **Verify access permissions**: The one-time token or JSON config must have access to the record
- **Check field name**: Ensure the field type (`password`, `login`, `text`, etc.) or custom field label exists in the record
- **Verify Application sharing**: The record must be shared to the Secrets Manager Application you're using
- **Check logs**: `ls -la /harness/secrets/` to see what files were created
- **Verify notation format**: Ensure the notation follows the correct format (e.g., `/field/password`, `/custom_field/MyLabel`, `/file/filename`)

### Expression Not Resolved

**Error:** Token preview shows `${...}` or `<+...>` unresolved

**Solutions:**
- Use `envVariables` (not `settings`) for Harness expressions when passing `KSM_CONFIG` to the plugin
- Verify secret name matches exactly
- Check secret scope matches the reference
- Ensure you're using the correct Harness expression syntax: `<+secrets.getValue("SECRET_NAME")>`

### Harness Expression Not Resolved

**Error:** `Harness expression not resolved`

**Solutions:**
- Ensure `KSM_CONFIG` is passed via `envVariables`, not `settings`
- Verify the secret exists and is accessible in the current scope
- Check that the Harness expression syntax is correct: `<+secrets.getValue("SECRET_NAME")>`

## Local Development

### Test Locally

```bash
# Set environment variables
export PLUGIN_SECRETS="JQPso5SMBpP29gKKGp6Enw/field/password > env:DB_PASSWORD"
export KSM_CONFIG="VVM6..." # Your base64 encoded token or JSON config

# Run the plugin
node ./src/index.js
```

### Project Structure

```
harness_keeper_plugin/
├── src/
│   └── index.js          # Main plugin logic
├── entrypoint.sh         # Container entrypoint script
├── Dockerfile            # Docker image definition
├── package.json          # Node.js dependencies
├── Example/
│   └── Pipeline.yaml     # Example Harness CI pipeline
└── README.md            # This file
```

## Example Pipeline

See `Example/Pipeline.yaml` for a complete working example that demonstrates:
- Plugin configuration
- Secret mapping with multiple record UIDs
- File-based secret consumption
- Error handling and failure strategies

## Support

For issues or questions:
- Check the [Keeper Security Documentation](https://docs.keeper.io/secrets-manager/)
- Review [Keeper Notation Documentation](https://docs.keeper.io/secrets-manager/secrets-manager/keeper-notation/)
- Review Harness CI documentation for plugin configuration
- Verify token format and Keeper record permissions

## License

ISC

## Version History

- **1.0.0** - Initial release
  - Zero-knowledge architecture implementation
  - Support for one-time tokens and JSON config
  - Keeper Notation support (field, custom_field, file)
  - File-based secret access
  - Base64 token decoding
  - Secure file permissions and cleanup
