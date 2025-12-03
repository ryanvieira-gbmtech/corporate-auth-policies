// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.spec.ts',
        '**/*.test.ts',
        '**/testUtils.ts'
      ]
    },
    // Configurações para o UI
    ui: true,
    open: false, // não abrir automaticamente
    api: {
      port: 51204, // porta padrão do Vitest UI
      host: 'localhost'
    }
  }
});