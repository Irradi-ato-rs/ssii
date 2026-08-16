// astro.config.mjs
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare({
    configPath: "./wrangler.jsonc",
    prerenderEnvironment: 'workerd',
    // CRITICAL: Re-integrate the consumer worker here
    auxiliaryWorkers: [
      {
        configPath: "./wrangler.consumer.jsonc",
      }
    ],
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