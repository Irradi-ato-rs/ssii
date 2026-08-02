import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  // Astro 5.18+ defaults to 'static', which works for WebUI + API routes
  adapter: cloudflare({
    platformProxy: { enabled: true },
  }),
});   
