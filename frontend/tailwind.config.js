/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
        sans: ["Inter", "system-ui", "sans-serif"],
      },
      colors: {
        bg: {
          primary: "#0d1117",
          secondary: "#111820",
          tertiary: "#161d27",
          elevated: "#1c2530",
        },
        border: {
          DEFAULT: "#1f2a37",
          strong: "#2d3a4b",
        },
        accent: {
          DEFAULT: "#3fb950",
          dim: "#2ea043",
        },
        danger: "#f85149",
        warning: "#d29922",
        info: "#58a6ff",
        violet: "#bc8cff",
      },
      spacing: {
        18: "4.5rem",
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
        glow: "0 0 0 3px rgba(63,185,80,0.18)",
        pop: "0 20px 60px -15px rgba(0,0,0,0.75), 0 0 0 1px rgba(255,255,255,0.04)",
      },
      keyframes: {
        "fade-in": { from: { opacity: "0" }, to: { opacity: "1" } },
        "pop-in": {
          from: { opacity: "0", transform: "translateY(-6px) scale(0.98)" },
          to: { opacity: "1", transform: "translateY(0) scale(1)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
      },
      animation: {
        "fade-in": "fade-in 0.15s ease-out",
        "pop-in": "pop-in 0.16s ease-out",
        shimmer: "shimmer 1.6s linear infinite",
      },
    },
  },
  plugins: [],
};
