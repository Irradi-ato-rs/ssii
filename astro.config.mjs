import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',
  adapter: cloudflare({
    prerenderEnvironment: 'workerd', // Required for SSR routes
  }),
  prerender: { default: false },
  image: { service: { entrypoint: 'astro/assets/services/sharp', config: { allowBuild: () => true } } },
  vite: { plugins: [tailwindcss()] }
});   