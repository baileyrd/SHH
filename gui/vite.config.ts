import { defineConfig } from "vite";

// Tauri expects a fixed dev-server port and a relative asset base so the
// built frontend loads correctly from the `tauri://` asset protocol.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
