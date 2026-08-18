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
  compressHTML: true,
});   