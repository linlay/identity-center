import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
import path from 'node:path';

function loadRootEnv(mode, cwd) {
  const rootDir = path.resolve(cwd, '..');
  return loadEnv(mode, rootDir, '');
}

function resolveProxyTarget(env, cwd) {
  const localFallback = 'http://localhost:8080';
  const configured = env.VITE_API_PROXY_TARGET;
  if (!configured) {
    return localFallback;
  }

  const isBackendHost = /:\/\/(?:backend|identity-center-backend)(?::|\/|$)/.test(configured);
  const runningInContainer = fs.existsSync('/.dockerenv');
  if (isBackendHost && !runningInContainer) {
    return localFallback;
  }

  return configured;
}

function createProxyEntry(target) {
  return {
    target,
    changeOrigin: true
  };
}

export default defineConfig(({ mode }) => {
  const env = loadRootEnv(mode, process.cwd());
  const base = env.VITE_BASE_PATH || '/admin/';
  const port = Number(env.VITE_DEV_PORT || env.FRONTEND_PORT || 11950);
  const strictPort = (env.VITE_DEV_STRICT_PORT || 'true').toLowerCase() !== 'false';
  const proxyPath = env.VITE_API_PROXY_PATH || '/admin/api';
  const proxyTarget = resolveProxyTarget(env, process.cwd());
  const proxy = {
    [proxyPath]: createProxyEntry(proxyTarget),
    '/api': createProxyEntry(proxyTarget),
    '/oauth2': createProxyEntry(proxyTarget),
    '/openid': createProxyEntry(proxyTarget)
  };

  return {
    plugins: [react()],
    base,
    server: {
      port: Number.isNaN(port) ? 11950 : port,
      strictPort,
      proxy
    }
  };
});
