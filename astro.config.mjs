import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// https://astro.build/config
export default defineConfig({
  site: 'https://ssii.fzoirm.com', // ADD THIS LINE
  adapter: cloudflare({
    platformProxy: { enabled: true },
  }),
  image: {
    service: {
      entrypoint: 'astro/assets/services/sharp',
      config: {
        // Allow sharp to run at build time only
        allowBuild: () => true, 
      }
    }
  }
});   
