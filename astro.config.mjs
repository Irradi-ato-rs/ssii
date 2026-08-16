import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// CRITICAL: Only load auxiliary workers in 'dev' mode
const isDev = process.argv.includes('dev');

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare({
    configPath: "./wrangler.jsonc",
    prerenderEnvironment: 'workerd',
    auxiliaryWorkers: isDev ? [
      {
        configPath: "./workers/wrangler.jsonc",
        config: {
          compatibility_flags: ["nodejs_compat"]
        }
      }
    ] : [], // Empty array for build/deploy
  }),
  prerender: {
    default: false,
  },
  image: {
    service: {
      entrypoint: 'astro/assets/services/sharp',
      config: {
        allowBuild: () => true, 
      }
    }
  }
});   