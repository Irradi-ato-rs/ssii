// astro.config.mjs
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare(),
  // Explicitly disable prerendering for all routes
  prerender: {
    default: false, // Forces SSR for all pages unless explicitly opted-in
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