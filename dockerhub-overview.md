# Keeper Secrets Manager Harness Plugin
Retrieve secrets from Keeper Vault directly into your Harness CI pipeline steps at runtime —
no secrets stored in Harness, no plaintext in pipeline configs.

## Documentation
For setup and usage, visit the [GitHub repository](https://github.com/Keeper-Security/harness-integration).

## How to Use This Image
```yaml
step:
  type: Plugin
  spec:
    image: keeper/harness-plugin:latest
    settings:
      ksm_config: <+secrets.getValue("Keeper_Config_Secret")>
      secrets: |
        RECORD_UID/field/password > DB_PASSWORD
```

## Support and Feedback
For support or bug reports, file an issue on our [GitHub page](https://github.com/Keeper-Security/harness-integration/issues).
