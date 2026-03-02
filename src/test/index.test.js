// Mock all external dependencies before requiring the module
jest.mock('@keeper-security/secrets-manager-core');
jest.mock('fs');
jest.mock('path');

const fs = require('fs');
const path = require('path');

describe('index.js - Complete Test Suite', () => {
    let getSecrets, getValue, localConfigStorage, downloadFile, initializeStorage;
    let mockExit, mockStderrWrite, mockConsoleLog;
    let originalEnv;

    // Helper to wait for async operations to complete
    const waitForAsync = async () => {
        // Wait multiple ticks to ensure all async operations complete
        for (let i = 0; i < 10; i++) {
            await new Promise(resolve => setImmediate(resolve));
        }
        // Also wait a small timeout to ensure all promises resolve
        await new Promise(resolve => setTimeout(resolve, 10));
    };

    beforeEach(() => {
        // Reset all mocks
        jest.clearAllMocks();
        jest.resetModules();

        // Save original environment
        originalEnv = { ...process.env };

        // Mock process methods
        mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {});
        mockStderrWrite = jest.spyOn(process.stderr, 'write').mockImplementation(() => {});
        mockConsoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});

        // Setup mocks for Keeper Secrets Manager
        getSecrets = jest.fn();
        getValue = jest.fn();
        localConfigStorage = jest.fn();
        downloadFile = jest.fn();
        initializeStorage = jest.fn();

        const secretsManagerCore = require('@keeper-security/secrets-manager-core');
        secretsManagerCore.getSecrets = getSecrets;
        secretsManagerCore.getValue = getValue;
        secretsManagerCore.localConfigStorage = localConfigStorage;
        secretsManagerCore.downloadFile = downloadFile;
        secretsManagerCore.initializeStorage = initializeStorage;

        // Setup fs mocks - need to get fresh references after resetModules
        const fsModule = require('fs');
        fs.mkdirSync = jest.fn();
        fs.writeFileSync = jest.fn();
        fs.chmodSync = jest.fn();
        // Also set on the module itself
        fsModule.mkdirSync = fs.mkdirSync;
        fsModule.writeFileSync = fs.writeFileSync;
        fsModule.chmodSync = fs.chmodSync;

        // Setup path mocks
        const pathModule = require('path');
        path.resolve = jest.fn((p) => `/resolved/${p}`);
        path.dirname = jest.fn((p) => {
            const parts = p.split('/');
            parts.pop();
            return parts.join('/') || '/';
        });
        path.join = jest.fn((...args) => args.join('/'));
        pathModule.resolve = path.resolve;
        pathModule.dirname = path.dirname;
        pathModule.join = path.join;

        // Clear environment variables
        delete process.env.PLUGIN_KSM_CONFIG;
        delete process.env.PLUGIN_SECRETS;
    });

    afterEach(() => {
        // Restore original environment
        process.env = originalEnv;
    });

    afterAll(() => {
        mockExit?.mockRestore();
        mockStderrWrite?.mockRestore();
        mockConsoleLog?.mockRestore();
    });

    describe('processToken - Error Cases', () => {
        test('should exit when rawToken is null', () => {
            delete process.env.PLUGIN_KSM_CONFIG;
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('KSM config is required'));
        });

        test('should exit when rawToken is undefined', () => {
            delete process.env.PLUGIN_KSM_CONFIG;
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when rawToken is empty string', () => {
            process.env.PLUGIN_KSM_CONFIG = '';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when token contains ${ Harness expression', () => {
            process.env.PLUGIN_KSM_CONFIG = '${harness.expression}';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Harness expression not resolved'));
        });

        test('should exit when token contains <+ Harness expression', () => {
            process.env.PLUGIN_KSM_CONFIG = '<+expression>';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when token contains ngSecretManager', () => {
            process.env.PLUGIN_KSM_CONFIG = 'ngSecretManager.token';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when token is empty after trim', () => {
            process.env.PLUGIN_KSM_CONFIG = '   ';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Token is null or empty'));
        });

        test('should exit when JSON config is missing hostname field', () => {
            const jsonConfig = JSON.stringify({ clientId: 'client', privateKey: 'key' });
            process.env.PLUGIN_KSM_CONFIG = jsonConfig;
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Missing required fields'));
        });

        test('should exit when JSON config is missing clientId field', () => {
            const jsonConfig = JSON.stringify({ hostname: 'test.com', privateKey: 'key' });
            process.env.PLUGIN_KSM_CONFIG = jsonConfig;
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when JSON config is missing privateKey field', () => {
            const jsonConfig = JSON.stringify({ hostname: 'test.com', clientId: 'client' });
            process.env.PLUGIN_KSM_CONFIG = jsonConfig;
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when JSON config is missing multiple fields', () => {
            const jsonConfig = JSON.stringify({ hostname: 'test.com' });
            process.env.PLUGIN_KSM_CONFIG = jsonConfig;
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should exit when JSON config is invalid', () => {
            process.env.PLUGIN_KSM_CONFIG = '{invalid json}';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Invalid JSON config'));
        });

        test('should exit when token format is invalid (not US: or JSON)', () => {
            process.env.PLUGIN_KSM_CONFIG = 'INVALID:token';
            require('../index');
            expect(mockExit).toHaveBeenCalledWith(1);
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Invalid token format'));
        });
    });

    describe('processToken - Success Cases', () => {
        test('should decode base64 token successfully', async () => {
            const base64Token = Buffer.from('US:decoded-token').toString('base64');
            process.env.PLUGIN_KSM_CONFIG = base64Token;
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(initializeStorage).toHaveBeenCalled();
        });

        test('should handle base64 decode error gracefully', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'invalid-base64!@#';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            // Should continue execution despite decode error
        });

        test('should parse valid JSON config', async () => {
            const jsonConfig = JSON.stringify({ hostname: 'test.com', clientId: 'client', privateKey: 'key' });
            process.env.PLUGIN_KSM_CONFIG = jsonConfig;
            process.env.PLUGIN_SECRETS = 'notation>output';
            const mockStorage = {};
            localConfigStorage.mockReturnValue(mockStorage);
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalledWith('/app/ksm-config.json', jsonConfig, 'utf8');
            expect(localConfigStorage).toHaveBeenCalledWith('/app/ksm-config.json');
        });

        test('should accept US: token format', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test-token';
            process.env.PLUGIN_SECRETS = 'notation>output';
            const mockStorage = {};
            localConfigStorage.mockReturnValue(mockStorage);
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(initializeStorage).toHaveBeenCalledWith(mockStorage, 'US:test-token');
        });

        test('should handle token with whitespace', async () => {
            process.env.PLUGIN_KSM_CONFIG = '  US:test-token  ';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(initializeStorage).toHaveBeenCalledWith(expect.anything(), 'US:test-token');
        });

        test('should call info function on plugin start', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            // Verify info was called with the startup message
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('INFO: Starting Keeper Secrets Manager plugin'));
        });

        test('should log base64 decode skip to stderr (no secret on stdout)', () => {
            // Base64 decode failure is logged to stderr only, never stdout — avoids leaking to Docker logs
            const originalBufferFrom = Buffer.from;
            Buffer.from = jest.fn(() => {
                throw new Error('Base64 decode error');
            });
            
            process.env.PLUGIN_KSM_CONFIG = 'not-us-format-token';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');
            
            require('../index');
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Base64 decode failed, using raw value'));
            
            Buffer.from = originalBufferFrom;
        });
    });

    describe('parseSecretMappings', () => {
        test('should treat env: prefix as literal destination name (no special parsing)', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>env:VAR_NAME';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalledWith('/harness/secrets/env:VAR_NAME', expect.any(Buffer));
        });

        test('should parse file: destination type', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should parse output destination type (default)', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle input without > separator', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle multiple > characters', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>part1>destination';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
        });

        test('should handle multiple secret mappings', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation1>env:VAR1\nnotation2>file:/path/file\nnotation3>output1';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(getValue).toHaveBeenCalledTimes(3);
        });

        test('should filter empty lines from multiline input', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation1>output1\n\nnotation2>output2\n  \nnotation3>output3';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(getValue).toHaveBeenCalledTimes(3);
        });

        test('should handle empty secrets input', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = '';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});

            require('../index');
            await waitForAsync();
            expect(getValue).not.toHaveBeenCalled();
        });
    });

    describe('runPlugin - File Handling', () => {
        test('should create /app directory', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            const mockStorage = {};
            localConfigStorage.mockReturnValue(mockStorage);
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            // Verify the async chain executed
            expect(initializeStorage).toHaveBeenCalled();
            expect(getSecrets).toHaveBeenCalled();
            // Check that mkdirSync was called for /app (first call in runPlugin)
            expect(fs.mkdirSync).toHaveBeenCalledWith('/app', { recursive: true });
        });

        test('should treat file: prefix as literal destination (writes to /harness/secrets/)', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('file-content');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalledWith('/harness/secrets/file:/path/to/file.txt', expect.any(Buffer));
        });

        test('should create /harness/secrets for any destination', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('file-content');
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(fs.mkdirSync).toHaveBeenCalledWith('/harness/secrets', { recursive: true });
        });

        test('should handle file secret with fileId', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            downloadFile.mockResolvedValue(Buffer.from('file-data'));
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalledWith({ fileId: 'file123' });
        });

        test('should handle file secret with fileUid', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileUid: 'file123' });
            downloadFile.mockResolvedValue(new Uint8Array([1, 2, 3]));
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalled();
        });

        test('should handle file secret with url', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ url: 'https://example.com/file' });
            downloadFile.mockResolvedValue(Buffer.from('file-data'));
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalled();
        });

        test('should handle file secret with /file/ notation', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'record/field/file/file.txt>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            // Return an object so isFileReference check passes
            // The notation includes '/file/' which will make notationIsFile true
            getValue.mockReturnValue({ someProperty: 'value' });
            downloadFile.mockResolvedValue(Buffer.from('file-data'));
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalled();
        });

        test('should handle downloadFile error gracefully', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            downloadFile.mockRejectedValue(new Error('Download failed'));
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Failed to download file'));
        });

        test('should handle Uint8Array file data', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            const uint8Array = new Uint8Array([1, 2, 3, 4]);
            downloadFile.mockResolvedValue(uint8Array);
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle Buffer file data', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            downloadFile.mockResolvedValue(Buffer.from('buffer-data'));
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle other file data types', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            // Return something that's not Uint8Array or Buffer to test the third branch
            downloadFile.mockResolvedValue('string-data');
            path.dirname.mockReturnValue('/path/to');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle file data that is neither Uint8Array nor Buffer (line 135 branch)', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            // Return something that's not Uint8Array or Buffer to test the third branch of ternary
            // Use an array to ensure it's not Uint8Array (regular array)
            downloadFile.mockResolvedValue([1, 2, 3]);
            path.dirname.mockReturnValue('/path/to');
            path.resolve.mockReturnValue('/path/to/file.txt');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalled();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle file data that is Buffer (line 134 branch)', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            // Return a Buffer (not Uint8Array) to test the Buffer.isBuffer branch
            // Note: In Node.js, Buffer IS a Uint8Array, so this tests the first branch
            const bufferData = Buffer.from('buffer-content');
            downloadFile.mockResolvedValue(bufferData);
            path.dirname.mockReturnValue('/path/to');
            path.resolve.mockReturnValue('/resolved/path/to/file.txt');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalled();
            expect(fs.writeFileSync).toHaveBeenCalledWith(expect.stringContaining('file.txt'), bufferData);
        });

        test('should handle file data that is plain Uint8Array (not Buffer)', async () => {
            // Test the second branch: Buffer.isBuffer is false but instanceof Uint8Array is true
            // Use a plain Uint8Array (not a Buffer) to test the middle branch of the ternary
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>file:/path/to/file.txt';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            
            // Create a plain Uint8Array (not a Buffer)
            // Buffer.isBuffer will return false, but instanceof Uint8Array will be true
            const uint8Array = new Uint8Array([1, 2, 3, 4, 5]);
            downloadFile.mockResolvedValue(uint8Array);
            path.dirname.mockReturnValue('/path/to');
            path.resolve.mockReturnValue('/resolved/path/to/file.txt');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalled();
            expect(fs.writeFileSync).toHaveBeenCalled();
            // Should convert Uint8Array to Buffer
            const writeCall = fs.writeFileSync.mock.calls.find(call => call[0].includes('file.txt'));
            expect(writeCall).toBeDefined();
        });
    });

    describe('runPlugin - Secret Value Handling', () => {
        test('should handle string secret value', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('string-secret');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle Buffer secret value', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(Buffer.from('buffer-secret'));

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle non-string, non-buffer secret value', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(12345);

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should skip secret when value is not found', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(null);

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('::warning::'));
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Value not found'));
        });

        test('should skip secret when value is undefined', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(undefined);

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('::warning::'));
        });
    });

    describe('runPlugin - Destination Types', () => {
        test('should handle env-prefixed destination as literal (writes to /harness/secrets/)', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>env:VAR_NAME';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('env-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalledWith('/harness/secrets/env:VAR_NAME', expect.any(Buffer));
            expect(fs.mkdirSync).toHaveBeenCalledWith('/harness/secrets', { recursive: true });
            expect(fs.chmodSync).toHaveBeenCalledWith('/harness/secrets/env:VAR_NAME', 0o600);
        });

        test('should handle env-prefixed destination with Buffer data', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>env:VAR_NAME';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(Buffer.from('buffer-env-value'));

            require('../index');
            await waitForAsync();
            const call = fs.writeFileSync.mock.calls.find(c => c[0] === '/harness/secrets/env:VAR_NAME');
            expect(call).toBeDefined();
            expect(call[1].toString('utf8')).toBe('buffer-env-value');
        });

        test('should handle env-prefixed destination with non-Buffer data', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>env:VAR_NAME';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(12345);

            require('../index');
            await waitForAsync();
            const call = fs.writeFileSync.mock.calls.find(c => c[0] === '/harness/secrets/env:VAR_NAME');
            expect(call).toBeDefined();
            expect(call[1].toString('utf8')).toBe('12345');
        });


        test('should create /harness/secrets directory for non-file destinations', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.mkdirSync).toHaveBeenCalledWith('/harness/secrets', { recursive: true });
        });

        test('should set file permissions to 0o600 for secret files', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.chmodSync).toHaveBeenCalledWith('/harness/secrets/output_var', 0o600);
        });

        test('should write only to /harness/secrets for output destinations', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output_var';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalledWith('/harness/secrets/output_var', expect.any(Buffer));
        });
    });

    describe('runPlugin - Error Handling', () => {
        test('should handle storage initialization error', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockRejectedValue(new Error('Storage initialization failed'));

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Failed:'));
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should handle token-related error with specific message', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockRejectedValue(new Error('Invalid token'));

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('One-time access tokens'));
        });

        test('should handle expired token error', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockRejectedValue(new Error('Token expired'));

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('One-time access tokens'));
        });

        test('should handle invalid token error', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockRejectedValue(new Error('invalid'));

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('One-time access tokens'));
        });

        test('should handle getSecrets error', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockRejectedValue(new Error('Failed to get secrets'));

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Failed:'));
            expect(mockExit).toHaveBeenCalledWith(1);
        });

        test('should handle generic error without token message', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockRejectedValue(new Error('Generic error'));

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('Failed:'));
            expect(mockStderrWrite).not.toHaveBeenCalledWith(expect.stringContaining('One-time access tokens'));
        });
    });

    describe('Edge Cases and Integration', () => {
        test('should handle null secret object', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue(null);

            require('../index');
            await waitForAsync();
            expect(mockStderrWrite).toHaveBeenCalledWith(expect.stringContaining('::warning::'));
        });

        test('should handle object secret without file properties', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ someProperty: 'value' });

            require('../index');
            await waitForAsync();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle object secret without file properties and notation without /file/', async () => {
            // Test the branch where typeof secret === 'object' && secret !== null is true
            // but (secret.fileId || secret.fileUid || secret.url || notationIsFile) is false
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'regular/notation>output';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            // Return an object without fileId, fileUid, url, and notation doesn't include '/file/'
            getValue.mockReturnValue({ regularProperty: 'value', anotherProp: 123 });

            require('../index');
            await waitForAsync();
            // Should treat it as a regular secret, not a file reference
            expect(downloadFile).not.toHaveBeenCalled();
            expect(fs.writeFileSync).toHaveBeenCalled();
        });

        test('should handle complex multiline input with mixed types', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'notation1>env:VAR1\nnotation2>file:/path/file\nnotation3>output1\nnotation4>env:VAR2';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue('secret-value');

            require('../index');
            await waitForAsync();
            expect(getValue).toHaveBeenCalledTimes(4);
        });

        test('should handle file notation with multiple file references', async () => {
            process.env.PLUGIN_KSM_CONFIG = 'US:test';
            process.env.PLUGIN_SECRETS = 'record1/field/file/file1.txt>file:/path/file1\nrecord2/field/file/file2.txt>file:/path/file2';
            localConfigStorage.mockReturnValue({});
            initializeStorage.mockResolvedValue();
            getSecrets.mockResolvedValue({});
            getValue.mockReturnValue({ fileId: 'file123' });
            downloadFile.mockResolvedValue(Buffer.from('file-data'));
            path.dirname.mockReturnValue('/path');

            require('../index');
            await waitForAsync();
            expect(downloadFile).toHaveBeenCalledTimes(2);
        });
    });
});
