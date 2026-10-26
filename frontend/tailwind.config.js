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
        },
        border: {
          DEFAULT: "#1f2a37",
        },
        accent: {
          DEFAULT: "#3fb950",
          dim: "#2ea043",
        },
        danger: "#f85149",
        warning: "#d29922",
      },
      spacing: {
        18: "4.5rem",
      },
    },
  },
  plugins: [],
};
