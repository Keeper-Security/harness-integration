const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2021,
            sourceType: 'script',
            globals: {
                ...globals.node
            }
        },
        rules: {
            'no-unused-vars': ['error', { 
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_'
            }],
            'no-console': 'off',
            'indent': ['error', 4],
            'quotes': ['error', 'single'],
            'semi': ['error', 'always']
        }
    },
    {
        // Jest test files configuration
        files: ['**/*.test.js', '**/__tests__/**/*.js'],
        languageOptions: {
            globals: {
                ...globals.jest
            }
        }
    },
    {
        ignores: [
            'node_modules/**',
            '*.vsix',
            'dist/**',
            'build/**',
            '.git/**'
        ]
    }
];
