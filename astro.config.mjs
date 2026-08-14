// astro.config.mjs
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare({
    prerenderEnvironment: 'node', // CRITICAL FIX / from 'workerd'
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