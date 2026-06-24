import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Vitest config. The only thing we need beyond defaults is the `@/*` path alias
 * (mirrors tsconfig.json) so server-side modules and their tests can import via
 * `@/lib/...` the same way the Next.js build does.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
});
