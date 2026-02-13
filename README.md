# Harness CI Keeper Plugin

Keeper Secrets Manager integration into Harness CI for dynamic secrets retrieval

## Overview

This plugin securely retrieves secrets from Keeper Security Secrets Manager and makes them available to subsequent steps in your Harness pipeline. The plugin implements a zero-knowledge architecture where secrets are retrieved directly from Keeper Vault at runtime and never pass through Harness systems in decrypted form.

## Features

- Retrieve secrets from the Keeper Vault within the Harness CI pipeline
- Support for standard fields, custom fields, and file attachments
- Zero-knowledge architecture - secrets retrieved directly from Keeper at runtime

All secret flow happens strictly between the plugin container and Keeper, while Harness provides orchestration, governance, and secure secret injection across the pipeline.

## Prerequisites

- Keeper Secrets Manager access with Application configured
- Harness CI account with project setup
- KSM configuration (one-time access token `US:...` or Base64-encoded token or JSON config)

## About

The plugin retrieves secrets from Keeper Secrets Manager and stores them in **Harness pipeline volume storage** at `/harness/secrets/` directory for reliable file-based access by subsequent steps.

**Important:** Secrets are stored in `/harness/secrets/` directory (Harness shared workspace volume), not as Harness environment variables.

All secrets are:
- **Pipeline-scoped**: Only accessible during the current pipeline execution
- **Automatically cleaned up**: Harness CI removes all secrets after pipeline completion
- **Securely stored**: Files have restricted permissions (600 - owner read/write only)

## Quick Start

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
                    image: dhborse/keeper-harness-plugin
                    settings:
                      secrets: |
                        RECORD_UID/field/password > PASSWORD
                        RECORD_UID/field/login > USERNAME
                    envVariables:
                      KSM_CONFIG: <+secrets.getValue("keeper_base64_secret")>
              - step:
                  type: Run
                  name: Use_Secrets
                  identifier: Use_Secrets
                  spec:
                    image: alpine:3.20
                    shell: Sh
                    command: |
                      if [ -f /harness/secrets/USERNAME ] && [ -f /harness/secrets/PASSWORD ]; then
                        USERNAME=$(cat /harness/secrets/USERNAME)
                        PASSWORD=$(cat /harness/secrets/PASSWORD)
                        echo "Username: $USERNAME"
                        echo "Password retrieved successfully"
                      else
                        echo "Error: Secret files not found"
                        exit 1
                      fi
```

## Inputs

### KSM_CONFIG

Keeper Secrets Manager configuration for authentication. Store in Harness secrets and reference:

```yaml
envVariables:
  KSM_CONFIG: <+secrets.getValue("Keeper_Config_Secret")>
```

**Supported Formats:**
- One-time access token: `US:xxxxx`
- JSON configuration: `{"hostname": "...", "clientId": "...", "privateKey": "..."}`
- Base64-encoded token or JSON config

### Secrets

Keeper Notation queries mapping secrets to destinations:

**Format:** `<keeper-notation> > <destination>`

**Example:**
```yaml
secrets: |
  RECORD_UID/field/password > PASSWORD
  RECORD_UID/field/login > USERNAME
```
Replace `RECORD_UID` with the actual Record UID from your Keeper Vault.

## Keeper Notation Format

The plugin supports three types of Keeper Notation queries:

| Type | Format | Example |
|------|--------|---------|
| **Standard Fields** | `<record-uid>/field/<field-type>` | `VeYTRo.../field/password` |
| **Custom Fields** | `<record-uid>/custom_field/<field-label>` | `VeYTRo.../custom_field/API_Key` |
| **File Attachments** | `<record-uid>/file/<file-name>` | `VeYTRo.../file/credentials.txt` |

**Note:** Record UID is the unique identifier for a secret record in Keeper. Get it from Keeper Vault → Record details → Record UID.

## Destination Format

The destination defines where the secret is stored:

| Format | Description | Output Location |
|--------|-------------|----------------|
| `VARIABLE_NAME` | Default output (recommended) | `/harness/secrets/VARIABLE_NAME` |

**Example:**
```yaml
# Saves to /harness/secrets/PASSWORD and /harness/secrets/USERNAME
RECORD_UID/field/password > PASSWORD
RECORD_UID/field/login > USERNAME
```

## Accessing Secrets

Secrets are stored in `/harness/secrets/` directory. Read them in subsequent steps:

```yaml
- step:
    type: Run
    name: Use_Secrets
    spec:
      image: alpine:3.20
      shell: Sh
      command: |
        USERNAME=$(cat /harness/secrets/USERNAME)
        PASSWORD=$(cat /harness/secrets/PASSWORD)
        # Use secrets in your build/deploy process
```

**Benefits:**
- Most reliable method
- No truncation issues
- Works with all secret types including binary files
- Supports long values and special characters

## Secret Storage

- **Location:** `/harness/secrets/` directory (Harness shared workspace volume)
- **Permissions:** `600` (owner read/write only)
- **Scope:** Pipeline execution only - automatically cleaned up after completion
- **Access:** Read files directly using `cat` or file operations

The `envVariables` section is **only** used to pass `KSM_CONFIG` to the plugin. Actual secrets are written to files in `/harness/secrets/` directory.

## Security

- **Zero-Knowledge**: Secrets retrieved directly from Keeper Vault at runtime
- **No Decrypted Storage**: Secrets never pass through Harness systems in decrypted form
- **Pipeline-Scoped**: All secrets scoped to current pipeline execution
- **Automatic Cleanup**: Harness CI removes secrets after pipeline completion
- **File Permissions**: Files have `600` permissions (owner read/write only)

### Best Practices

1. Use one-time access tokens instead of permanent credentials
2. Base64 encode tokens before storing in Harness secrets
3. Clean up secret files after use in pipeline steps
4. Use appropriate secret scope (project/org/account)
5. Verify Record UIDs before configuring pipelines

## Troubleshooting

| Error | Solution |
|-------|----------|
| `KSM config is required` | Verify secret exists and expression `<+secrets.getValue("SECRET_NAME")>` is correct |
| `Invalid token format` | Check token starts with `US:` or `{` for JSON config |
| `Value not found for notation` | Verify Record UID, field name (case-sensitive), and Application permissions |
| `Failed to download file` | Check file exists in record, name matches exactly, and Application has file access permissions |
| `Harness expression not resolved` | Verify secret reference expression and secret scope (project/org/account) |

## Version History

- **1.0.0** - Initial release
  - Zero-knowledge architecture implementation
  - Support for one-time tokens and JSON config
  - Keeper Notation support (field, custom_field, file)
  - File-based secret access
  - Base64 token decoding
  - Secure file permissions and cleanup

## References

- [Keeper Notation Documentation](https://docs.keeper.io/en/keeperpam/secrets-manager/about/keeper-notation)
- [Keeper Secrets Manager Quick Start Guide](https://docs.keeper.io/en/keeperpam/secrets-manager/quick-start-guide)