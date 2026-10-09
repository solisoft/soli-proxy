# TUI screenshots

**These images are mockups, not captures.** They are drawn by
`scripts/tui_screenshots.py` with representative sample data, because the real
TUI needs a live daemon, a terminal and an admin password to render anything.

The layout, palette and key hints are mirrored from the source by hand:

| Image element                  | Source of truth            |
| ------------------------------ | -------------------------- |
| palette, sidebar, panel chrome | `src/tui/theme.rs`         |
| screen composition             | `src/tui/screens/*.rs`     |
| footer hints, help overlay     | `src/tui/app.rs`           |

If you change any of those, re-run the script and compare the result against the
real TUI:

```sh
python3 scripts/tui_screenshots.py   # needs Pillow
```

The website's landing page replays the dashboard too, as live text rather than
an image: `www/public/js/tui.js`. Same sources, same rule. It also mirrors the
dashboard's geometry (`render_strip`, `render_flow`, `render_side`), the glyphs
in `screens/common.rs` and `anim.rs`, and the journal wording in `events.rs` and
`app.rs`. Its header comment lists which function each part follows. Its
sidebar version comes from `data-version` in `www/app/views/home/index.html.erb`.

A mockup that has drifted from the shipped UI is worse than no mockup — if you
cannot keep these current, delete them rather than leaving them stale.
