#!/usr/bin/env python3
"""Render mockups of the Soli Proxy TUI for the docs.

These are drawn, not captured: the TUI needs a live daemon, a terminal and a
password prompt, none of which a docs build has. The layout, palette and copy
below are therefore kept in lockstep with the real code by hand:

    palette + sidebar + list_block  ->  src/tui/theme.rs
    screen composition              ->  src/tui/screens/*.rs
    footer and help text            ->  src/tui/app.rs

If you change any of those, re-run this script and eyeball the result against
the real thing. A mockup that has drifted from the UI is worse than no mockup.
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# The TUI is laid out for a wide terminal; 118x34 matches a maximised window.
COLS, ROWS = 118, 34
CW, CH = 8, 16
W, H = COLS * CW, ROWS * CH

# ── palette: mirrors src/tui/theme.rs ──────────────────────────────────
ACCENT = (0, 212, 170)
ACCENT_DIM = (0, 120, 100)
SUCCESS = (80, 250, 123)
WARN = (255, 184, 108)
DANGER = (255, 85, 85)
MUTED = (98, 114, 164)
FG = (248, 248, 242)
SELECT_BG = (15, 55, 52)
SIDEBAR_BG = (18, 22, 28)
INK = (10, 12, 16)
MAGENTA = (189, 147, 249)
CYAN_3XX = (139, 233, 253)

# ── theme.rs constants ─────────────────────────────────────────────────
SIDEBAR_WIDTH = 16
NAV_TOP_OFFSET = 3
SCREEN_SHORT = ["dash", "routes", "apps", "circuits", "errors", "config"]
VERSION = "0.29.2"

BODY_X = SIDEBAR_WIDTH
BODY_W = COLS - SIDEBAR_WIDTH
BODY_H = ROWS - 1  # last row is the footer
FOOTER_Y = ROWS - 1

OUT = Path("docs/tui-screenshots")

FONT_CANDIDATES = [
    "/System/Library/Fonts/Menlo.ttc",
    "/System/Library/Fonts/Monaco.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/Library/Fonts/DejaVuSansMono.ttf",
]


def load_font():
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, 12)
            except OSError:
                continue
    raise SystemExit(
        "No monospace font found. Add one to FONT_CANDIDATES in this script."
    )


FONT = load_font()


# ── cell-grid primitives ───────────────────────────────────────────────


def put(img, x, y, text, fg=FG, bg=None):
    """Draw `text` starting at character cell (x, y), clipped to the grid."""
    if y < 0 or y >= ROWS or x >= COLS:
        return
    text = text[: max(0, COLS - x)]
    if not text:
        return
    draw = ImageDraw.Draw(img)
    px, py = x * CW, y * CH
    if bg:
        draw.rectangle([px, py, px + len(text) * CW - 1, py + CH - 1], fill=bg)
    draw.text((px, py + 1), text, font=FONT, fill=fg)


def fill(img, x, y, w, h, color):
    ImageDraw.Draw(img).rectangle(
        [x * CW, y * CH, (x + w) * CW - 1, (y + h) * CH - 1], fill=color
    )


def list_block(img, x, y, w, h, title):
    """theme::list_block — a left rule plus an inverted title chip.

    Returns the content rect (theme::body): one column in, one row down.
    """
    for i in range(h):
        put(img, x, y + i, "│", ACCENT_DIM)
    put(img, x + 1, y, f" {title} ", INK, ACCENT)
    return x + 1, y + 1, w - 1, h - 1


def kpi(img, x, y, w, h, value, label, color):
    """theme::kpi — left rule, value on the first row, label under it."""
    for i in range(h):
        put(img, x, y + i, "│", color)
    put(img, x + 2, y, value, color)
    put(img, x + 2, y + 1, label, MUTED)


def bar(img, x, y, cells, color):
    """A solid horizontal bar. Drawn as a rectangle rather than repeated "█"
    so it fills the cell the way a terminal does, whatever the font."""
    if cells <= 0:
        return
    fill(img, x, y, cells, 1, color)


def sparkline(img, x, y, w, h, values, color):
    """ratatui's Sparkline: one column per sample, bars grown from the bottom."""
    peak = max(values) or 1
    for i, value in enumerate(values[-w:]):
        filled = value / peak * h
        full = int(filled)
        for row in range(full):
            fill(img, x + i, y + h - 1 - row, 1, 1, color)
        frac = filled - full
        if frac > 0.125 and full < h:
            # Partial top cell: an eighth-block, approximated by a part-height rect.
            top = y + h - 1 - full
            px, py = (x + i) * CW, top * CH
            height = max(1, round(CH * frac))
            ImageDraw.Draw(img).rectangle(
                [px, py + CH - height, px + CW - 1, py + CH - 1], fill=color
            )


def pct_split(x, w, *weights):
    """Ratatui's Percentage constraints across `w` columns."""
    total = sum(weights)
    out, cur = [], x
    for i, weight in enumerate(weights):
        cw = w - (cur - x) if i == len(weights) - 1 else round(w * weight / total)
        out.append((cur, cw))
        cur += cw
    return out


# ── chrome ─────────────────────────────────────────────────────────────


def sidebar(img, active):
    fill(img, 0, 0, SIDEBAR_WIDTH, ROWS, SIDEBAR_BG)
    put(img, 0, 0, " SOLI", INK, ACCENT)
    put(img, 0, 1, " proxy", MUTED, SIDEBAR_BG)
    for i, short in enumerate(SCREEN_SHORT):
        marker = "▸" if i == active else " "
        label = f" {marker} {i + 1} {short:<8}"
        if i == active:
            put(img, 0, NAV_TOP_OFFSET + i, label, ACCENT, SELECT_BG)
        else:
            put(img, 0, NAV_TOP_OFFSET + i, label, MUTED, SIDEBAR_BG)
    put(img, 0, ROWS - 2, f" v{VERSION}", MUTED, SIDEBAR_BG)
    put(img, 0, ROWS - 1, " 1-6  ?", ACCENT_DIM, SIDEBAR_BG)


def chrome(active, keys, daemon=("● ", SUCCESS, "daemon")):
    img = Image.new("RGB", (W, H), INK)
    sidebar(img, active)
    put(img, BODY_X, FOOTER_Y, f" {keys} ", MUTED)
    glyph, color, name = daemon
    badge = f" {name} {glyph}"
    put(img, COLS - len(badge) - 1, FOOTER_Y, badge, color)
    return img


NAV_KEYS = "1-6 nav"


# ── screens ────────────────────────────────────────────────────────────


def dashboard():
    img = chrome(0, f"{NAV_KEYS}  Tab cycle  r  ?  q")

    # Row 0: four KPI tiles (Length(4)).
    tiles = pct_split(BODY_X, BODY_W, 25, 25, 25, 25)
    for (x, w), (value, label, color) in zip(
        tiles,
        [
            ("12.4K", "requests", ACCENT),
            ("42", "req / s", SUCCESS),
            ("18.2ms", "avg latency", WARN),
            ("0.10%", "error rate", DANGER),
        ],
    ):
        kpi(img, x, 0, w, 4, value, label, color)

    # Row 1: live rps sparkline | http status bars (Length(6)).
    (sx, sw), (hx, hw) = pct_split(BODY_X, BODY_W, 55, 45)
    cx, cy, cw, ch = list_block(img, sx, 4, sw, 6, "live rps  42")
    series = [
        12, 18, 27, 19, 24, 36, 31, 22, 17, 29, 44, 33, 25, 13, 19, 26, 34, 41,
        28, 20, 14, 21, 30, 39, 47, 35, 27, 18, 12, 20, 28, 33, 40, 46, 38, 31,
        24, 17, 11, 19, 26, 32, 39, 34, 27, 21, 15, 42,
    ]
    sparkline(img, cx, cy, cw, ch, series, ACCENT)

    cx, cy, cw, _ = list_block(img, hx, 4, hw, 6, "http")
    bar_w = cw - 16
    for i, (code, count, pct, color) in enumerate(
        [
            ("2xx", "12.1K", 0.965, SUCCESS),
            ("3xx", "180", 0.014, CYAN_3XX),
            ("4xx", "142", 0.011, WARN),
            ("5xx", "12", 0.010, DANGER),
        ]
    ):
        put(img, cx, cy + i, code, color)
        put(img, cx + 5, cy + i, count, FG)
        bar(img, cx + 14, cy + i, round(bar_w * pct), color)

    # Row 2: four meta tiles (Length(6)).
    tiles = pct_split(BODY_X, BODY_W, 25, 25, 25, 25)
    for (x, w), (value, label, color) in zip(
        tiles,
        [
            ("2h 14m 8s", "up  0.0.0.0:80  :443", ACCENT),
            ("3/4", "apps running", SUCCESS),
            ("8", "routes", MAGENTA),
            ("5", "circuits", SUCCESS),
        ],
    ):
        kpi(img, x, 10, w, 6, value, label, color)

    # Row 3: apps overview | server detail (Min(6)).
    (ax, aw), (vx, vw) = pct_split(BODY_X, BODY_W, 58, 42)
    cx, cy, _, _ = list_block(img, ax, 16, aw, BODY_H - 16, "apps")
    put(img, cx, cy, "name        domain                slot     status    port", MUTED)
    apps = [
        ("api", "api.example.com", "blue", "● run", SUCCESS, ":8081"),
        ("web", "www.example.com", "green", "● run", SUCCESS, ":8082"),
        ("docs", "docs.example.com", "blue", "● run", SUCCESS, ":8083"),
        ("legacy", "old.example.com", "blue", "○ stop", MUTED, "-"),
    ]
    for i, (name, domain, slot, status, color, port) in enumerate(apps):
        row = cy + 1 + i
        put(img, cx, row, name, FG)
        put(img, cx + 12, row, domain, MUTED)
        put(img, cx + 34, row, slot, MUTED)
        put(img, cx + 43, row, status, color)
        put(img, cx + 53, row, port, MUTED)

    cx, cy, _, _ = list_block(img, vx, 16, vw, BODY_H - 16, "server")
    server = [
        ("listen", "0.0.0.0:80", FG),
        ("https", ":443", FG),
        ("tls", "acme", FG),
        ("admin", "127.0.0.1:9090", FG),
        ("auth", "enabled", FG),
        ("scripts", "auth.lua", MAGENTA),
        ("in flight", "3", FG),
        ("bytes in", "4.10 MB", FG),
        ("bytes out", "82.3 MB", FG),
        ("tls conns", "1.3K", FG),
        ("errors", "12", DANGER),
    ]
    for i, (key, value, color) in enumerate(server):
        put(img, cx, cy + i, key, MUTED)
        put(img, cx + 10, cy + i, value, color)
    return img


def _table(img, x, y, w, h, title, header, rows, selected=0):
    cx, cy, cw, _ = list_block(img, x, y, w, h, title)
    put(img, cx, cy, header, ACCENT)
    for i, cells in enumerate(rows):
        row = cy + 1 + i
        if i == selected:
            fill(img, cx, row, cw, 1, SELECT_BG)
        for col, text, color in cells:
            put(img, cx + col, row, text, FG if i == selected else color)
    return cx, cy, cw


def routes():
    img = chrome(1, f"{NAV_KEYS}  j/k  a add  e edit  d delete  /  r  ?  q")
    rows = [
        [(0, "0", MUTED), (4, "api.example.com", FG), (26, "http://127.0.0.1:8081", FG),
         (52, "-", MUTED), (60, "auth.lua", MAGENTA), (72, "round_robin", MUTED)],
        [(0, "1", MUTED), (4, "www.example.com", FG), (26, "http://127.0.0.1:8082", FG),
         (52, "2 users", SUCCESS), (60, "-", MUTED), (72, "least_conn", MUTED)],
        [(0, "2", MUTED), (4, "docs.example.com", FG), (26, "http://127.0.0.1:8083", FG),
         (52, "-", MUTED), (60, "-", MUTED), (72, "round_robin", MUTED)],
        [(0, "3", MUTED), (4, "/api/v2/*", FG), (26, "http://10.0.0.4:9000 +2", FG),
         (52, "1 user", SUCCESS), (60, "rate.lua", MAGENTA), (72, "ip_hash", MUTED)],
        [(0, "4", MUTED), (4, "^/static/(.*)$", FG), (26, "http://127.0.0.1:8090", FG),
         (52, "-", MUTED), (60, "-", MUTED), (72, "round_robin", MUTED)],
    ]
    _table(
        img, BODY_X, 0, BODY_W, BODY_H, "routes",
        "#   Matcher               Targets                   Auth    Scripts     LB",
        rows, selected=1,
    )
    return img


def apps():
    img = chrome(2, f"{NAV_KEYS}  j/k  Enter action  /  r  ?  q")
    rows = [
        [(0, "api", FG), (12, "api.example.com", MUTED), (34, "Running", SUCCESS),
         (45, "2.4%", FG), (53, "128.4 MB", FG), (65, "8.2K", FG), (73, "4", DANGER), (81, "12.1ms", FG)],
        [(0, "web", FG), (12, "www.example.com", MUTED), (34, "Running", SUCCESS),
         (45, "1.1%", FG), (53, "96.0 MB", FG), (65, "3.4K", FG), (73, "0", FG), (81, "8.4ms", FG)],
        [(0, "docs", FG), (12, "docs.example.com", MUTED), (34, "Running", SUCCESS),
         (45, "0.3%", FG), (53, "42.1 MB", FG), (65, "612", FG), (73, "0", FG), (81, "6.0ms", FG)],
        [(0, "legacy", FG), (12, "old.example.com", MUTED), (34, "Stopped", MUTED),
         (45, "-", MUTED), (53, "-", MUTED), (65, "0", FG), (73, "0", FG), (81, "-", MUTED)],
    ]
    _table(
        img, BODY_X, 0, BODY_W, BODY_H, "apps",
        "Name        Domain                Status     CPU     Memory      Reqs    Errors  Avg RT",
        rows, selected=0,
    )
    return img


def circuits():
    img = chrome(3, f"{NAV_KEYS}  j/k  r  ?  q")
    rows = [
        [(0, "http://127.0.0.1:8081", FG), (40, "closed", SUCCESS), (52, "0", FG), (66, "8241", FG)],
        [(0, "http://127.0.0.1:8082", FG), (40, "closed", SUCCESS), (52, "0", FG), (66, "3402", FG)],
        [(0, "http://10.0.0.4:9000", FG), (40, "open", DANGER), (52, "12", FG), (66, "0", FG)],
        [(0, "http://10.0.0.5:9000", FG), (40, "half_open", WARN), (52, "5", FG), (66, "2", FG)],
        [(0, "http://127.0.0.1:8090", FG), (40, "closed", SUCCESS), (52, "1", FG), (66, "612", FG)],
    ]
    _table(
        img, BODY_X, 0, BODY_W, BODY_H, "circuits",
        "Target                                  State       Failures      Successes",
        rows, selected=2,
    )
    return img


def errors():
    img = chrome(4, f"{NAV_KEYS}  j/k  Enter detail  r  ?  q")
    rows = [
        [(0, "14:02:11", MUTED), (10, "502", DANGER), (16, "GET", FG), (22, "api.example.com", FG), (40, "/v1/orders", FG)],
        [(0, "14:02:44", MUTED), (10, "504", DANGER), (16, "POST", FG), (22, "api.example.com", FG), (40, "/v1/checkout", FG)],
        [(0, "14:05:02", MUTED), (10, "failed", DANGER), (16, "GET", FG), (22, "old.example.com", FG), (40, "/legacy/report", FG)],
        [(0, "14:09:37", MUTED), (10, "500", DANGER), (16, "GET", FG), (22, "www.example.com", FG), (40, "/account/settings", FG)],
        [(0, "14:11:20", MUTED), (10, "502", DANGER), (16, "GET", FG), (22, "api.example.com", FG), (40, "/v1/orders", FG)],
    ]
    _table(
        img, BODY_X, 0, BODY_W, BODY_H, "errors  5",
        "Time      Status  Method  Host              Path",
        rows, selected=3,
    )
    return img


def config():
    img = chrome(5, f"{NAV_KEYS}  j/k  r  ?  q")
    cx, cy, cw, _ = list_block(img, BODY_X, 0, BODY_W, BODY_H, "proxy.conf")
    text = [
        "[server]",
        'bind = "0.0.0.0:80"',
        "https_port = 443",
        "",
        "[tls]",
        'mode = "acme"',
        'acme_email = "ops@example.com"',
        "",
        "[admin]",
        'bind = "127.0.0.1:9090"',
        "enabled = true",
        'username = "admin"',
        "",
        "[[rules]]",
        'matcher = { domain = "api.example.com" }',
        'targets = [{ url = "http://127.0.0.1:8081" }]',
        'scripts = ["auth.lua"]',
        "",
        "[[rules]]",
        'matcher = { domain = "www.example.com" }',
        'targets = [{ url = "http://127.0.0.1:8082" }]',
        'load_balancing = "least_conn"',
    ]
    for i, line in enumerate(text):
        put(img, cx, cy + i, line, FG)
    hint = " 1-32 of 214 · j/k "
    put(img, cx + cw - len(hint), 0, hint, MUTED)
    return img


def help_overlay():
    img = dashboard()
    # theme::centered_modal(body, 64, 22) over the body area.
    w, h = 64, 22
    x = BODY_X + (BODY_W - w) // 2
    y = (BODY_H - h) // 2
    fill(img, x, y, w, h, INK)
    cx, cy, _, _ = list_block(img, x, y, w, h, "help")
    text = [
        "  1-6            Jump to screen     Tab / S-Tab  Cycle",
        "  j/k  PgUp/Dn   Move               g / G        First / last",
        "  /              Search             r            Refresh now",
        "  Enter          Select / open      Esc          Back",
        "  a/e/d          Route add/edit/del",
        "  Mouse          Click nav, click rows, wheel scrolls",
        "  q              Quit",
        "",
        "  Apps: Enter -> Deploy / Restart / Stop / Rollback / Logs",
        "  Errors: Enter detail · y copy (OSC 52)",
        "",
        "  Any key closes this overlay",
    ]
    for i, line in enumerate(text):
        put(img, cx, cy + i, line, FG)
    return img


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    shots = {
        "01-dashboard.png": dashboard,
        "02-routes.png": routes,
        "03-apps.png": apps,
        "04-circuits.png": circuits,
        "05-errors.png": errors,
        "06-config.png": config,
        "07-help.png": help_overlay,
    }
    for name, fn in shots.items():
        path = OUT / name
        fn().save(path)
        print(path)


if __name__ == "__main__":
    main()
