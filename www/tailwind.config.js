/** @type {import('tailwindcss').Config} */
const defaultTheme = require('tailwindcss/defaultTheme')

module.exports = {
  content: [
    // .slv must be listed explicitly: brace expansion matches the whole
    // extension, so "html.erb" never covered "html.slv" and the classes used
    // only in .slv views were silently dropped from the build.
    "./app/views/**/*.{erb,html,slv,html.erb,html.slv}",
    "./app/controllers/**/*.sl",
    "./public/js/**/*.js"
  ],
  theme: {
    extend: {
      // Geist / Geist Mono, loaded from Google Fonts in the layout. Declared
      // here too so `font-sans` and `font-mono` mean the same faces: code
      // blocks styled with `font-mono` used to fall back to the system
      // monospace while bare <code> got the webfont.
      fontFamily: {
        sans: ['Geist', ...defaultTheme.fontFamily.sans],
        mono: ['"Geist Mono"', ...defaultTheme.fontFamily.mono],
      },
      // The terminal UI's palette (src/tui/theme.rs), as CSS variables set in
      // app/assets/css/application.css. The site wears the product's colours.
      colors: {
        primary: '#059669',
        secondary: '#06b6d4',
        ink: 'var(--ink)',
        panel: 'var(--panel)',
        select: 'var(--select)',
        fg: 'var(--fg)',
        muted: 'var(--muted)',
        soft: 'var(--soft)',
        accent: 'var(--accent)',
        'accent-dim': 'var(--accent-dim)',
        ok: 'var(--ok)',
        warn: 'var(--warn)',
        danger: 'var(--danger)',
        magenta: 'var(--magenta)',
        cyan: 'var(--cyan)',
        rule: 'var(--rule)',
      }
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
