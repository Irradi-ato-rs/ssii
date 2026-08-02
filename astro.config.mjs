// astro.config.mjs
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  integrations: [tailwind()],
  adapter: cloudflare({
    platformProxy: { enabled: true },
    imageService: 'compile',
  }),
});   
