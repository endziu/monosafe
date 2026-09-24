import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests/browser',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: 0,
    workers: process.env.CI ? 2 : undefined,
    reporter: process.env.CI ? 'github' : 'list',
    use: {
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure'
    },
    projects: ['chromium', 'firefox', 'webkit'].map(browserName => ({
        name: browserName,
        use: { browserName }
    }))
});
