/** @type {import('tailwindcss').Config} */
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
