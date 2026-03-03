const { 
    getSecrets, 
    getValue, 
    localConfigStorage, 
    downloadFile,
    initializeStorage
} = require('@keeper-security/secrets-manager-core');
const fs = require('fs');
const path = require('path');

const KSM_CONFIG_PATH = '/app/ksm-config.json';
const REQUIRED_FIELDS = ['hostname', 'clientId', 'privateKey'];

const core = {
    getMultilineInput: (name) => {
        const val = process.env[`PLUGIN_${name.toUpperCase()}`] || '';
        return val.split('\n').filter(line => line.trim() !== '');
    },
    info: (msg) => process.stderr.write(`INFO: ${msg}\n`),
    error: (msg) => process.stderr.write(`::error::${msg}\n`),
    warning: (msg) => process.stderr.write(`::warning::${msg}\n`)
};

const splitInput = (text) => {
    const n = text.lastIndexOf('>');
    return n < 0 ? [text, ''] : [text.substring(0, n).trim(), text.substring(n + 1).trim()];
};

const processToken = (rawToken) => {
    if (!rawToken) {
        core.error('KSM config is required');
        core.error('Set PLUGIN_KSM_CONFIG (or ksm_config in settings)');
        process.exit(1);
    }

    let token = rawToken.trim();

    if (token.includes('${') || token.includes('<+') || token.includes('ngSecretManager')) {
        core.error('Harness expression not resolved');
        process.exit(1);
    }

    // Decode base64 if needed
    if (!token.startsWith('US:') && !token.startsWith('{')) {
        try {
            token = Buffer.from(token, 'base64').toString('utf-8').trim();
        } catch {
            // Not base64, use as-is
            core.warning('Base64 decode failed, using raw value');
        }
    }

    token = token.trim();
    if (!token) {
        core.error('Token is null or empty');
        process.exit(1);
    }

    const isConfigJson = token.startsWith('{');
    
    if (isConfigJson) {
        try {
            const config = JSON.parse(token);
            const missing = REQUIRED_FIELDS.filter(f => !config[f]);
            if (missing.length) {
                core.error(`Missing required fields: ${missing.join(', ')}`);
                process.exit(1);
            }
            return { token, isConfigJson: true, config };
        } catch (e) {
            core.error(`Invalid JSON config: ${e.message}`);
            process.exit(1);
        }
    }

    if (!token.startsWith('US:')) {
        core.error('Invalid token format - expected US:xxxxx or JSON config');
        process.exit(1);
    }

    return { token, isConfigJson: false, config: null };
};

const parseSecretMappings = () => {
    return core.getMultilineInput('secrets').map(line => {
        const [notation, destRaw] = splitInput(line);
        return { notation, destination: destRaw, destinationType: 'output' };
    });
};

const setupStorage = async (token, isConfigJson, config) => {
    if (isConfigJson) {
        fs.writeFileSync(KSM_CONFIG_PATH, JSON.stringify(config), 'utf8');
        return localConfigStorage(KSM_CONFIG_PATH);
    }
    const storage = localConfigStorage(KSM_CONFIG_PATH);
    await initializeStorage(storage, token);
    return storage;
};

const runPlugin = async () => {
    try {
        core.info('Starting Keeper Secrets Manager plugin');
        fs.mkdirSync('/app', { recursive: true });

        const { token, isConfigJson, config } = processToken(process.env.PLUGIN_KSM_CONFIG);
        const inputs = parseSecretMappings();
        const storage = await setupStorage(token, isConfigJson, config);
        const secrets = await getSecrets({ storage });

        for (const input of inputs) {
            const secret = getValue(secrets, input.notation);
            if (!secret) {
                core.warning(`Value not found for notation: ${input.notation}`);
                continue;
            }

            const notationIsFile = input.notation.includes('/file/');
            const isFileReference = typeof secret === 'object' && 
                secret !== null && 
                (secret.fileId || secret.fileUid || secret.url || notationIsFile);

            let data;
            
            if (isFileReference) {
                try {
                    const fileData = await downloadFile(secret);
                    data = Buffer.isBuffer(fileData) ? fileData : 
                        fileData instanceof Uint8Array ? Buffer.from(fileData) : 
                            Buffer.from(fileData);
                } catch (downloadError) {
                    core.error(`Failed to download file for notation ${input.notation}: ${downloadError.message}`);
                    continue;
                }
            } else {
                data = Buffer.isBuffer(secret) ? secret : 
                    typeof secret === 'string' ? Buffer.from(secret, 'utf8') : 
                        Buffer.from(String(secret), 'utf8');
            }

            fs.mkdirSync('/harness/secrets', { recursive: true });
            const secretFilePath = path.join('/harness/secrets', input.destination);
            fs.writeFileSync(secretFilePath, data);
            fs.chmodSync(secretFilePath, 0o600);
        }
    } catch (error) {
        core.error(`Failed: ${error.message}`);
        if (error.message.includes('token') || error.message.includes('invalid') || error.message.includes('expired')) {
            core.error('One-time access tokens are single-use - generate a new token');
        }
        process.exit(1);
    }
};

runPlugin();