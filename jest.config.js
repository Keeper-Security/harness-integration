module.exports = {
    testEnvironment: 'node',
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/**/*.test.js',
    ],
    coverageThreshold: {
        global: {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100,
        },
    },
    testMatch: [
        '**/__tests__/**/*.js',
        '**/*.test.js',
    ],
    verbose: true,
};
