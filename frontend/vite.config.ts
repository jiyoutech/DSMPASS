import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:25000",
      "/healthz": "http://127.0.0.1:25000",
      "/readyz": "http://127.0.0.1:25000"
    }
  }
});

