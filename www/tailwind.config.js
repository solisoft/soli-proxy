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
      colors: {
        primary: '#059669',
        secondary: '#06b6d4',
      }
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
