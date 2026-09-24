
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {},
      fontFamily: {
        display: ['IBM Plex Sans', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'monospace'],
        sans: ['IBM Plex Sans', 'system-ui', '-apple-system', 'sans-serif'],
        cond: ['IBM Plex Sans Condensed', 'IBM Plex Sans', 'system-ui', 'sans-serif'],
      }
    }
  },
  plugins: [],
}
