import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api/graph": { target: "http://localhost:8005", rewrite: p => p.replace(/^\/api\/graph/, "") },
      "/api/cert":  { target: "http://localhost:8006", rewrite: p => p.replace(/^\/api\/cert/, "") },
    },
  },
});
