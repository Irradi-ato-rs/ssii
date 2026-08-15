// astro.config.mjs
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// CRITICAL: Only load auxiliary workers during build/deploy, not dev
const isDev = process.argv.includes('dev');

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare({
    configPath: "./wrangler.jsonc",
    prerenderEnvironment: 'workerd',
    // Only attach auxiliary workers when NOT in dev mode
    auxiliaryWorkers: isDev ? [] : [
      {
        configPath: "./workers/wrangler.jsonc",
        config: {
          compatibility_flags: ["nodejs_compat"]
        }
      }
    ]
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