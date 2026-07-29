import { defineConfig } from 'vite';

export default defineConfig({
  base: '/project/termlens/',
  build: {
    outDir: 'dist/client',
    emptyOutDir: true
  }
});
