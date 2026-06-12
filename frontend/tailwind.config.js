/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // AionUi design tokens — neutral, dense, ops-friendly.
        aion: {
          bg: "#0b1020",
          surface: "#11172b",
          surface2: "#161e36",
          border: "#1f2742",
          text: "#e6ebf5",
          muted: "#8a93a6",
          accent: "#5eead4",
          accent2: "#60a5fa",
          warn: "#f59e0b",
          danger: "#ef4444",
          ok: "#22c55e",
          info: "#38bdf8",
        },
        severity: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#f59e0b",
          low: "#38bdf8",
          info: "#94a3b8",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(94,234,212,0.25), 0 8px 24px -8px rgba(94,234,212,0.25)",
      },
    },
  },
  plugins: [],
};
