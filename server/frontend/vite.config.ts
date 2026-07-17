import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiTarget = process.env.VITE_API_TARGET || 'http://localhost:8000'
const devPort = Number(process.env.VITE_DEV_PORT || 5173)

export default defineConfig({
  plugins: [react()],
  server: {
    port: devPort,
    proxy: {
      '/health': { target: apiTarget, changeOrigin: true },
      '/stats': { target: apiTarget, changeOrigin: true },
      '/agents': { target: apiTarget, changeOrigin: true },
      '/threat-intel': { target: apiTarget, changeOrigin: true },
      '/rules': { target: apiTarget, changeOrigin: true },
      '/auth': { target: apiTarget, changeOrigin: true },
      '/admin': { target: apiTarget, changeOrigin: true },
      '/delete-my-data': { target: apiTarget, changeOrigin: true },
      '/hosts': { target: apiTarget, changeOrigin: true },
      '/process-tree': { target: apiTarget, changeOrigin: true },
      '/events': { target: apiTarget, changeOrigin: true },
      '/amsi': { target: apiTarget, changeOrigin: true },
      '/download-db': { target: apiTarget, changeOrigin: true },
      '/ai': { target: apiTarget, changeOrigin: true },
      '/deploy': { target: apiTarget, changeOrigin: true },
    },
  },
})
