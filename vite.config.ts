import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { ruleRepoPlugin } from './src/server/ruleRepoPlugin';

export default defineConfig({
  plugins: [react(), ruleRepoPlugin()],
});
