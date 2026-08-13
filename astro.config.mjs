import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://ssii.fzoirm.com',
  output: 'server',

  adapter: cloudflare({
    entryPoint: './src/worker.ts', // Astro to use custom file
    prerenderEnvironment: 'workerd',
  }),

  prerender: {
    default: false,
  },

  image: {
    service: {
      entrypoint: 'astro/assets/services/sharp',
      config: { allowBuild: () => true }
    }
  },

  vite: {
    plugins: [tailwindcss()]
  }
});   