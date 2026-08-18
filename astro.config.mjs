// astro.config.mjs
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare({
    configPath: "./wrangler.jsonc",
    prerenderEnvironment: 'workerd',
    auxiliaryWorkers: [
      {
        configPath: "./wrangler.consumer.jsonc",
      }
    ],
  }),
  vite: {
    plugins: [tailwindcss()],
  },
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