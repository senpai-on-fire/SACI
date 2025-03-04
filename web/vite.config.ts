import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import yaml from '@modyfi/vite-plugin-yaml'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), yaml()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
