import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Every backend router prefix is proxied to the API so the browser talks to a
// single origin (the httpOnly session cookie and the CSRF cookie are then
// first-party). The SPA itself uses a HashRouter (/#/leaks, /#/audit, ...), so
// its client routes can never collide with these prefixes.
const API = 'http://127.0.0.1:8000';
const PREFIXES = ['/auth', '/users', '/tenants', '/api-keys', '/leaks', '/watchlist', '/sources',
  '/recon', '/yara', '/notifications', '/ai', '/system', '/intel', '/surface', '/vulns', '/brand', '/ransomware', '/domains', '/report'];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(PREFIXES.map((p) => [p, { target: API, changeOrigin: false }])),
  },
  preview: {
    proxy: Object.fromEntries(PREFIXES.map((p) => [p, { target: API, changeOrigin: false }])),
  },
});
