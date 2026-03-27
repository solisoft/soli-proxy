/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/views/**/*.{erb,html,html.erb}",
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
