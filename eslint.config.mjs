import js from '@eslint/js';
import ts from 'typescript-eslint';
export default ts.config(
  { ignores: ['**/dist/**', '**/build/**', '**/node_modules/**', 'docs/research/**', '.cogniflow-llm-router/**'] },
  js.configs.recommended,
  ...ts.configs.recommended,
  { languageOptions: { globals: { console: 'readonly', process: 'readonly', Buffer: 'readonly', URL: 'readonly', Request: 'readonly', Response: 'readonly', fetch: 'readonly', document: 'readonly', window: 'readonly', setTimeout: 'readonly', clearTimeout: 'readonly', setInterval: 'readonly', clearInterval: 'readonly', AbortController: 'readonly', TextEncoder: 'readonly', TextDecoder: 'readonly', crypto: 'readonly', structuredClone: 'readonly', navigator: 'readonly', localStorage: 'readonly', indexedDB: 'readonly', atob: 'readonly', btoa: 'readonly', performance: 'readonly' } } },
);
