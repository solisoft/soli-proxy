// The terminal UI's dashboard, replayed on the landing page.
//
// Drawn, not captured, like scripts/tui_screenshots.py: the real TUI needs a
// daemon, a terminal and a password. Layout, glyphs, palette and wording are
// mirrored from the source by hand, so they drift unless kept in step:
//
//   palette, sidebar, tabs, put / fit / bars  ->  src/tui/theme.rs
//   strip, traffic tree, http / memory / events  ->  src/tui/screens/dashboard.rs
//   links and packets, life glyphs, stepper  ->  src/tui/screens/common.rs, src/tui/anim.rs
//   journal wording                           ->  src/tui/events.rs, src/tui/app.rs
//   footer hints                              ->  src/tui/app.rs (render_footer)
//
// The scene is a pure function of its clock `t` (seconds into a 28 s loop):
// seeking to a chapter is drawing another `t`, nothing is replayed.
//
// Pages are swapped without a reload (/__soli/nav.js), so this runs as an
// idempotent init() on load and on every `soli:load`, stopping the previous
// page's loop first.
(function () {
    "use strict";

    var LOOP = 28;
    var TICK = 0.1; // the TUI redraws at about 10 fps while something moves

    // ── the scene ─────────────────────────────────────────────────────────

    // Chapters: [start, still frame shown when motion is off].
    var CHAPTERS = [
        [0, 3.3],    // blue-green deploy
        [8, 9.7],    // wake from sleep
        [12.5, 13.3], // bot trapped
        [16, 16.9],  // maintenance
        [20, 22.6],  // 5xx burst
    ];

    var DEPLOY = { app: "shop", slot: "green", wake: false, start: 1.0, health: 1.9, swtch: 3.1, drain: 3.6, drainSecs: 2, done: 5.2, keep: 2.6 };
    var WAKE = { app: "blog", slot: "blue", wake: true, start: 8.8, health: 9.1, done: 9.5, keep: 2.4 };
    var MAINT_AT = 16.5;
    var ERR_FROM = 20.6, ERR_TO = 25.0;

    var APPS = ["shop", "api", "docs", "crm", "blog", "legacy"];

    function rps(app, t) {
        switch (app) {
            case "shop": return 38 + 6 * Math.sin(t * 0.7) + 3 * Math.sin(t * 2.3);
            case "api": return 26 + 5 * Math.sin(t * 0.5 + 1) + 2 * Math.sin(t * 1.9);
            case "docs": return 9 + 2 * Math.sin(t * 0.9 + 2);
            case "crm": return t < MAINT_AT ? 3.2 + Math.sin(t * 1.1) : 0;
            case "blog": return t < WAKE.done ? 0 : 1.6 + 0.6 * Math.sin(t * 1.3);
            default: return 0;
        }
    }

    function eps(app, t) {
        return app === "api" && t >= ERR_FROM && t < ERR_TO ? rps(app, t) * 0.22 : 0;
    }

    function totalRps(t) {
        var s = 0;
        for (var i = 0; i < APPS.length; i++) s += rps(APPS[i], t);
        return s;
    }

    // common.rs `life`, for the scene's apps.
    function life(app, t) {
        if (app === "crm" && t >= MAINT_AT) return "maintenance";
        if (app === "blog") {
            if (t < WAKE.start) return "asleep";
            if (t < WAKE.done) return "waking";
        }
        if (app === "shop" && t >= DEPLOY.start && t < DEPLOY.done) return "deploying";
        if (app === "legacy") return "stopped";
        if (eps(app, t) > 0) return "erroring";
        return "running";
    }

    function idleLink(l) {
        return l === "asleep" || l === "stopped" || l === "failed" || l === "waking" || l === "maintenance";
    }

    function deployOf(app, t) {
        var d = app === DEPLOY.app ? DEPLOY : app === WAKE.app ? WAKE : null;
        if (!d || t < d.start || t >= d.done + d.keep) return null;
        return d;
    }

    // Journal, oldest first. Times before 0 were before the scene began; blog
    // went to sleep less than two minutes ago, which keeps it on the traffic
    // panel (dashboard.rs RECENTLY_ASLEEP).
    var JOURNAL = [
        [-212, "docs", "deploy → blue", "deploy"],
        [-209.6, "docs", "live on blue in 2.4 s", "done"],
        [-95, "blog", "asleep · 12 min idle", "asleep"],
        [DEPLOY.start, "shop", "deploy → green", "deploy"],
        [DEPLOY.swtch, "shop", "traffic → green", "traffic"],
        [DEPLOY.done, "shop", "live on green in " + (DEPLOY.done - DEPLOY.start).toFixed(1) + " s", "done"],
        [WAKE.start, "blog", "waking · a request", "waking"],
        [WAKE.done, "blog", "awake in " + (WAKE.done - WAKE.start).toFixed(1) + " s", "done"],
        [13.0, "203.0.113.7", "banned · trap /.env", "ban"],
        [MAINT_AT, "crm", "maintenance on → 18:30", "maintenance"],
        [20.9, "api.example.com", "502 /v1/orders", "error"],
        [22.4, "api.example.com", "502 /v1/orders", "error"],
        [23.7, "api.example.com", "504 /v1/orders", "error"],
    ];

    // dashboard.rs kind_color
    var KIND = {
        deploy: "c-wa", waking: "c-wa", traffic: "c-ac", done: "c-ok",
        failed: "c-da", error: "c-da", asleep: "c-ma", maintenance: "c-wa", ban: "c-da",
    };

    var CLOCK0 = 14 * 3600 + 21 * 60 + 7; // the wall clock at t = 0

    function clock(t) {
        var s = ((Math.floor(CLOCK0 + t) % 86400) + 86400) % 86400;
        return pad2(Math.floor(s / 3600)) + ":" + pad2(Math.floor(s / 60) % 60) + ":" + pad2(s % 60);
    }

    // ── formatting: theme.rs / dashboard.rs ───────────────────────────────

    function pad2(n) { return (n < 10 ? "0" : "") + n; }

    function fmtNum(n) {
        if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
        if (n >= 1e4) return (n / 1e3).toFixed(1) + "K";
        return String(Math.round(n));
    }

    function fmtMs(ms) {
        if (ms >= 1000) return (ms / 1000).toFixed(2) + "s";
        if (ms >= 1) return ms.toFixed(1) + "ms";
        return Math.round(ms * 1000) + "us";
    }

    function fmtBytes(b) {
        var G = 1073741824, M = 1048576;
        if (b >= G) return (b / G).toFixed(2) + " GB";
        if (b >= M) return (b / M).toFixed(2) + " MB";
        return (b / 1024).toFixed(2) + " KB";
    }

    function fmtRate(r) { return r >= 100 ? r.toFixed(0) : r.toFixed(1); }

    function rjust(s, n) { while (s.length < n) s = " " + s; return s; }

    function fit(s, w) {
        var c = Array.from(s);
        if (c.length <= w) return s + " ".repeat(w - c.length);
        if (w === 0) return "";
        return c.slice(0, w - 1).join("") + "…";
    }

    function bars(vals) {
        var L = "▁▂▃▄▅▆▇█", max = 0;
        vals.forEach(function (v) { if (v > max) max = v; });
        return vals.map(function (v) {
            return max <= 0 ? "▁" : L[Math.max(0, Math.min(7, Math.round((v / max) * 7)))];
        }).join("");
    }

    var SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
    function spinner(t) { return SPINNER[Math.floor(t * 10) % 10]; }
    function snore(t) { return ["z  ", "zZ ", "zZz"][Math.floor(t * 1.6) % 3]; }

    // anim.rs packet_positions / is_error_packet
    function packets(len, rate, t) {
        if (len === 0 || rate <= 0) return [];
        var max = Math.max(1, Math.floor(len / 3));
        var n = Math.max(1, Math.min(max, Math.round(1 + Math.log2(1 + rate) * 1.4)));
        var speed = 9 + Math.min(rate * 0.6, 14);
        var out = [];
        for (var i = 0; i < n; i++) {
            var p = t * speed + (i * len) / n;
            out.push(Math.floor(((p % len) + len) % len) % len);
        }
        return out;
    }

    function isErrorPacket(i, ratio) {
        if (ratio <= 0) return false;
        var every = Math.max(1, Math.round(1 / Math.min(ratio, 1)));
        return i % every === 0;
    }

    // A per-second figure glides to its new value (anim.rs tween, cubic
    // ease-out) instead of flickering at every frame. With motion off it lands
    // at once, as in the TUI.
    function tween(f, t, motion) {
        var k = Math.floor(t), b = f(k);
        if (!motion) return b;
        var a = f(k - 1), x = Math.min(1, (t - k) / 0.4);
        return a + (b - a) * (1 - Math.pow(1 - x, 3));
    }

    // ── the cell grid ─────────────────────────────────────────────────────

    function Grid(cols, rows) {
        this.cols = cols;
        this.rows = rows;
        this.ch = new Array(cols * rows).fill(" ");
        this.st = new Array(cols * rows).fill("");
    }

    // theme.rs `put`: write at (x, y) relative to `area`, clipped to it.
    // Returns the columns written.
    Grid.prototype.put = function (area, x, y, text, style) {
        if (y < 0 || y >= area.h || x >= area.w) return 0;
        var chars = Array.from(text), n = Math.min(chars.length, area.w - x);
        for (var i = 0; i < n; i++) {
            var cx = area.x + x + i, cy = area.y + y;
            if (cx < 0 || cx >= this.cols || cy >= this.rows) continue;
            var k = cy * this.cols + cx;
            this.ch[k] = chars[i];
            // A cell keeps its background when only the foreground is set.
            var bg = this.st[k].match(/\bb-\w+/);
            this.st[k] = style + (bg && !/\bb-/.test(style) ? " " + bg[0] : "");
        }
        return n;
    };

    // theme.rs `shade`
    Grid.prototype.shade = function (area, x, y, w, bg) {
        for (var i = 0; i < w && x + i < area.w; i++) {
            var k = (area.y + y) * this.cols + area.x + x + i;
            this.st[k] = (this.st[k].replace(/\s*\bb-\w+/, "") + " " + bg).trim();
        }
    };

    function esc(c) {
        return c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c;
    }

    // Runs of one style become one span. Anything outside ASCII sits in a
    // one-cell box: box drawing, braille and blocks may come from a fallback
    // font with another advance, and must not push the rest of the row.
    Grid.prototype.html = function () {
        var out = "";
        for (var y = 0; y < this.rows; y++) {
            var x = 0;
            while (x < this.cols) {
                var k = y * this.cols + x, s = this.st[k], run = "";
                while (x < this.cols && this.st[y * this.cols + x] === s) {
                    var c = this.ch[y * this.cols + x];
                    run += c.charCodeAt(0) > 126 ? "<i>" + c + "</i>" : esc(c);
                    x++;
                }
                out += s ? '<span class="' + s + '">' + run + "</span>" : run;
            }
            if (y + 1 < this.rows) out += "\n";
        }
        return out;
    };

    // ── screens ───────────────────────────────────────────────────────────

    var SCREEN_SHORT = ["dash", "routes", "apps", "circuits", "errors", "config"];
    var CHIP = "c-ink b-ac w-b";
    var SIDEBAR_WIDTH = 16, SIDEBAR_MIN_WIDTH = 140; // theme.rs
    var SIDE = 28, SIDE_MIN_TOTAL = 96; // dashboard.rs

    // theme.rs render_sidebar
    function sidebar(g, a, version) {
        for (var y = 0; y < a.h; y++) g.put(a, 0, y, " ".repeat(a.w), "b-pa");
        g.put(a, 0, 0, " SOLI", CHIP);
        g.put(a, 0, 1, " proxy", "c-mu b-pa");
        SCREEN_SHORT.forEach(function (s, i) {
            var on = i === 0;
            g.put(a, 0, 3 + i, " " + (on ? "▸" : " ") + " " + (i + 1) + " " + (s + "        ").slice(0, 8),
                on ? "c-ac b-se w-b" : "c-mu b-pa");
        });
        g.put(a, 0, a.h - 2, " v" + version, "c-mu b-pa");
        g.put(a, 0, a.h - 1, " 1-6  ?", "c-ad b-pa");
    }

    // theme.rs render_tabs
    function tabs(g, a, version) {
        g.put(a, 0, 0, " ".repeat(a.w), "b-pa");
        var x = g.put(a, 0, 0, " SOLI ", CHIP) + 1;
        SCREEN_SHORT.forEach(function (s, i) {
            x += g.put(a, x, 0, " " + (i + 1) + " " + s + " ", i === 0 ? "c-ac b-se w-b" : "c-mu b-pa");
        });
        var v = "v" + version + " ";
        if (a.w > x + v.length) g.put(a, a.w - v.length, 0, v, "c-mu b-pa");
    }

    function memory(t) {
        var awake = t >= WAKE.done;
        return {
            apps: (412.5 + (awake ? 38.2 : 0)) * 1048576,
            n: awake ? 5 : 4,
            total: 8 * 1073741824,
            avail: (4.61 - (awake ? 0.04 : 0)) * 1073741824,
        };
    }

    function counts(t) {
        var req = 21893000 + 82 * t;
        var e5 = t < ERR_FROM ? 0 : Math.round(5.7 * (Math.min(t, ERR_TO) - ERR_FROM));
        return { req: req, c2: req * 0.928, c3: req * 0.041, c4: req * 0.031, c5: e5 };
    }

    // dashboard.rs render_strip
    function strip(g, a, t, s) {
        g.put(a, 0, 1, "─".repeat(a.w), "c-ad");
        var c = counts(t);
        var hist = [];
        for (var k = Math.floor(t) - 15; k <= Math.floor(t); k++) hist.push(Math.round(totalRps(k)));
        var lat = tween(function (k) { return 3.4 + 0.4 * Math.sin(k * 0.8) + (eps("api", k) > 0 ? 1.7 : 0); }, t, s.motion);
        var answered = c.c2 + c.c3 + c.c4 + c.c5;
        var rate5 = (c.c5 / answered) * 100;
        var mem = memory(t);
        var running = APPS.filter(function (n) {
            var l = life(n, t);
            return l !== "asleep" && l !== "stopped";
        }).length;
        var groups = [
            [[fmtNum(c.req), "c-ac w-b"], [" requests", "c-mu"]],
            [[String(Math.round(tween(totalRps, t, s.motion))), "c-ok w-b"], [" req/s ", "c-mu"], [bars(hist), "c-ac"]],
            [[fmtMs(lat), "c-wa w-b"], [" latency", "c-mu"]],
            [[rate5.toFixed(2) + " %", (c.c5 > 0 ? "c-da" : "c-ok") + " w-b"], [" 5xx", "c-mu"]],
            [["up ", "c-mu"], ["3d04h", "c-fg"]],
            [[running + "/" + APPS.length, "c-fg"], [" apps", "c-mu"]],
            [["38", "c-cy w-b"], [" on", "c-mu"], [" · 4 ws", "c-mu"]],
            [[fmtBytes(mem.apps), "c-ma w-b"], [" in apps", "c-mu"]],
            [[fmtBytes(mem.avail), "c-ok w-b"], [" free", "c-mu"]],
            [["12", "c-fg"], [" routes", "c-mu"]],
        ];
        var x = 1;
        for (var i = 0; i < groups.length; i++) {
            var w = groups[i].reduce(function (n, p) { return n + Array.from(p[0]).length; }, 0);
            if (x + w > a.w) break;
            groups[i].forEach(function (p) { x += g.put(a, x, 0, p[0], p[1]); });
            x += 3;
        }
    }

    // common.rs link
    function link(g, a, x, y, len, rate, err, dotted, t) {
        if (dotted) {
            var d = "";
            for (var i = 0; i < len; i++) d += i % 2 === 0 ? "·" : " ";
            g.put(a, x, y, d, "c-mu");
            return;
        }
        g.put(a, x, y, "─".repeat(len), "c-ad");
        packets(len, rate, t).forEach(function (p, i) {
            var bad = isErrorPacket(i, err);
            g.put(a, x + p, y, bad ? "x" : "o", (bad ? "c-da" : "c-ac") + " w-b");
        });
    }

    // common.rs stepper
    function stepper(g, a, x, y, d, t) {
        var stages = d.wake ? [["start", d.start], ["health", d.health]] :
            [["start", d.start], ["health", d.health], ["switch", d.swtch], ["drain", d.drain]];
        var names = ["start", "health", "switch", "drain"], cur = 0;
        stages.forEach(function (st, i) { if (t >= st[1]) cur = i; });
        var cx = x;
        names.forEach(function (name, i) {
            var label, style;
            if (i === cur) {
                label = spinner(t) + name;
                if (name === "drain" && d.drainSecs) label += " " + Math.max(0, d.drainSecs - Math.floor(t - d.drain)) + "s";
                style = "c-ink b-wa w-b";
            } else if (i < cur) {
                label = "✓" + name;
                style = "c-ok";
            } else {
                label = " " + name;
                style = "c-mu";
            }
            cx += g.put(a, cx, y, label, style);
            if (i + 1 < names.length) cx += g.put(a, cx, y, " › ", "c-mu");
        });
    }

    function glyph(l, t) {
        switch (l) {
            case "maintenance": return ["◆", "c-wa"];
            case "waking": case "deploying": return [spinner(t), "c-wa"];
            case "erroring": return ["●", "c-wa"];
            case "running": return ["●", "c-ok"];
            case "asleep": return ["◐", "c-ma"];
            default: return ["○", "c-mu"];
        }
    }

    // dashboard.rs render_flow
    function flow(g, a, t, s) {
        g.put(a, 0, 0, " traffic ", CHIP);
        // Phones get a shorter lead-in; everything after it is the TUI's.
        var narrow = a.w < 70;
        var lead = narrow ? 4 : 16;
        var arrowX = 9 + lead, tx = arrowX + 3, linkLen = narrow ? 8 : 14;
        var total = tween(totalRps, t, s.motion);
        g.put(a, 1, 2, "clients", "c-fg");
        link(g, a, 9, 2, lead, total, 0, false, t);
        g.put(a, arrowX, 2, "▶", "c-ac");
        var x = arrowX + 2;
        x += g.put(a, x, 2, (total > 0 ? spinner(t) : "●") + " soli-proxy", "c-ac w-b");
        g.put(a, x + 1, 2, ":443 · v" + s.version, "c-mu");

        g.put(a, tx, 3, "│", "c-ad");
        var l1 = tx + 1 + linkLen;
        // The TUI's name column, narrowed so the longest status here
        // ("maintenance → 18:30") still fits where a terminal would clip it.
        var nameW = Math.max(narrow ? 6 : 10, Math.min(30, a.w - (l1 + 4 + 10), a.w - (l1 + 4 + 1 + 19)));
        var rateX = l1 + 4 + nameW + 1;

        var shown = [], quiet = 0;
        APPS.forEach(function (n) {
            var l = life(n, t);
            if (l === "stopped") quiet++;
            else shown.push(n);
        });

        var y = 4;
        shown.forEach(function (n, i) {
            var last = i + 1 === shown.length;
            var l = life(n, t), r = tween(function (k) { return rps(n, k); }, t, s.motion);
            var e = eps(n, t), d = deployOf(n, t);
            g.put(a, tx, y, last ? "└" : "├", "c-ad");
            link(g, a, tx + 1, y, linkLen, rps(n, t), r > 0 ? Math.min(1, e / r) : 0, idleLink(l), t);
            if (l === "waking" && t - WAKE.start < 0.8) {
                // The request that woke it, on its way down the dotted line.
                var p = Math.floor(Math.min(1, (t - WAKE.start) / 0.8) * (linkLen - 1));
                g.put(a, tx + 1 + p, y, "o", "c-ac w-b");
            }
            g.put(a, l1, y, idleLink(l) && l !== "waking" ? " " : "▶", "c-ac");
            var gl = glyph(l, t);
            g.put(a, l1 + 2, y, gl[0], gl[1]);
            g.put(a, l1 + 4, y, fit(n, nameW), l === "asleep" ? "c-mu" : "c-fg");
            if (l === "maintenance") g.put(a, rateX, y, "maintenance → 18:30", "c-wa");
            else if (l === "asleep") g.put(a, rateX, y, snore(t), "c-ma");
            else if (l === "waking") g.put(a, rateX, y, "waking", "c-wa");
            else {
                if (e > 0) g.put(a, rateX - 2, y, "▲", "c-da w-b");
                g.put(a, rateX, y, rjust(fmtRate(r), 5) + "/s", e > 0 ? "c-da" : "c-fg");
            }
            y++;
            if (d) {
                g.put(a, tx, y, last ? " " : "│", "c-ad");
                var sx = tx + 3;
                if (t >= d.done) {
                    var took = (d.done - d.start).toFixed(1);
                    g.put(a, sx, y, "✓ " + (d.wake ? "awake" : "live on " + d.slot) + " in " + took + " s", "c-ok");
                } else {
                    var w = g.put(a, sx, y, d.wake ? "waking " : "→ " + d.slot + " ", "c-wa");
                    stepper(g, a, sx + w, y, d, t);
                }
                y++;
            }
        });
        if (quiet > 0) g.put(a, tx + 1, Math.min(y, a.h - 1), " · " + quiet + " without traffic", "c-mu");
    }

    function journal(t) {
        return JOURNAL.filter(function (e) { return e[0] <= t; }).reverse();
    }

    // anim.rs fade_level: fresh for a second, fading until three, then plain.
    function fade(age, motion) {
        if (!motion) return null;
        return age < 1 ? "b-fr" : age < 3 ? "b-fa" : null;
    }

    // dashboard.rs render_side: http, memory, events
    function side(g, a, t, s) {
        g.put(a, 1, 0, " http ", CHIP);
        var c = counts(t), total = c.c2 + c.c3 + c.c4 + c.c5, barW = a.w - 13;
        [["2xx", c.c2, "c-ok"], ["3xx", c.c3, "c-cy"], ["4xx", c.c4, "c-wa"], ["5xx", c.c5, "c-da"]].forEach(function (row, i) {
            g.put(a, 1, 2 + i, row[0], row[2] + " w-b");
            g.put(a, 5, 2 + i, rjust(fmtNum(row[1]), 6), "c-fg");
            if (row[1] > 0) g.put(a, 12, 2 + i, "█".repeat(Math.max(1, Math.round((row[1] / total) * barW))), row[2]);
        });

        var m = memory(t), y = 7;
        g.put(a, 1, y, " memory ", CHIP);
        var w = a.w - 2, used = m.total - m.avail;
        var cells = function (b) { return Math.round((b / m.total) * w); };
        var ca = Math.min(cells(m.apps), w), cu = Math.max(ca, Math.min(w, cells(used)));
        g.put(a, 1, y + 2, "█".repeat(ca), "c-ma");
        g.put(a, 1 + ca, y + 2, "▓".repeat(cu - ca), "c-mu");
        g.put(a, 1 + cu, y + 2, "·".repeat(w - cu), "c-ad");
        var x = 1 + g.put(a, 1, y + 3, "apps  ", "c-mu");
        x += g.put(a, x, y + 3, fmtBytes(m.apps), "c-ma w-b");
        g.put(a, x, y + 3, " · " + m.n + " apps", "c-mu");
        x = 1 + g.put(a, 1, y + 4, "used  ", "c-mu");
        x += g.put(a, x, y + 4, fmtBytes(used), "c-fg");
        g.put(a, x, y + 4, " / " + fmtBytes(m.total), "c-mu");
        x = 1 + g.put(a, 1, y + 5, "free  ", "c-mu");
        x += g.put(a, x, y + 5, fmtBytes(m.avail), "c-ok w-b");
        g.put(a, x, y + 5, " · " + Math.round((m.avail / m.total) * 100) + " %", "c-mu");

        var top = y + 7;
        g.put(a, 1, top, " events ", CHIP);
        var first = top + 2, rows = Math.floor((a.h - first) / 2);
        journal(t).slice(0, rows).forEach(function (e, i) {
            var ey = first + i * 2, bg = fade(t - e[0], s.motion);
            if (bg) { g.shade(a, 0, ey, a.w, bg); g.shade(a, 0, ey + 1, a.w, bg); }
            var fresh = bg === "b-fr" ? "c-wa" : bg === "b-fa" ? "c-ff" : null;
            g.put(a, 1, ey, clock(e[0]), fresh || "c-mu");
            g.put(a, 10, ey, fit(e[1], a.w - 11), fresh || "c-fg");
            g.put(a, 3, ey + 1, fit(e[2], a.w - 4), fresh || KIND[e[3]]);
        });
    }

    // dashboard.rs render_memory_line
    function memoryLine(g, a, t) {
        var m = memory(t), used = m.total - m.avail, W = 12;
        var x = g.put(a, 0, 0, " memory ", CHIP) + 2;
        var cells = function (b) { return Math.round((b / m.total) * W); };
        var ca = Math.min(cells(m.apps), W), cu = Math.max(ca, Math.min(W, cells(used)));
        x += g.put(a, x, 0, "█".repeat(ca), "c-ma");
        x += g.put(a, x, 0, "▓".repeat(cu - ca), "c-mu");
        x += g.put(a, x, 0, "·".repeat(W - cu), "c-ad") + 2;
        x += g.put(a, x, 0, fmtBytes(m.apps), "c-ma w-b");
        x += g.put(a, x, 0, " apps   ", "c-mu");
        x += g.put(a, x, 0, fmtBytes(used), "c-fg");
        x += g.put(a, x, 0, "/" + fmtBytes(m.total) + " used   ", "c-mu");
        x += g.put(a, x, 0, fmtBytes(m.avail), "c-ok w-b");
        g.put(a, x, 0, " free", "c-mu");
    }

    // dashboard.rs render_journal_compact
    function journalCompact(g, a, t, s) {
        g.put(a, 0, 0, " events ", CHIP);
        journal(t).slice(0, a.h - 1).forEach(function (e, i) {
            var y = 1 + i, bg = fade(t - e[0], s.motion);
            if (bg) g.shade(a, 0, y, a.w, bg);
            // The TUI's 24 columns, less on a phone so the event text shows.
            var appW = Math.min(24, Math.max(8, a.w - 36));
            g.put(a, 1, y, clock(e[0]), "c-mu");
            g.put(a, 10, y, fit(e[1], appW), "c-fg");
            g.put(a, 11 + appW, y, e[2], KIND[e[3]]);
        });
    }

    // dashboard.rs render, inside app.rs's frame (nav, body, footer).
    function draw(cols, t, s) {
        var wide = cols >= SIDEBAR_MIN_WIDTH;
        var rows = cols - (wide ? SIDEBAR_WIDTH + 1 : 0) >= SIDE_MIN_TOTAL ? 28 : 24;
        var g = new Grid(cols, rows);
        var full = { x: 0, y: 0, w: cols, h: rows };
        var main;
        if (wide) {
            sidebar(g, { x: 0, y: 0, w: SIDEBAR_WIDTH, h: rows - 1 }, s.version);
            main = { x: SIDEBAR_WIDTH + 1, y: 0, w: cols - SIDEBAR_WIDTH - 1, h: rows - 1 };
        } else {
            tabs(g, { x: 0, y: 0, w: cols, h: 1 }, s.version);
            main = { x: 0, y: 1, w: cols, h: rows - 2 };
        }

        strip(g, { x: main.x, y: main.y, w: main.w, h: 2 }, t, s);
        var body = { x: main.x, y: main.y + 2, w: main.w, h: main.h - 2 };
        if (body.w >= SIDE_MIN_TOTAL) {
            for (var y = 0; y < body.h; y++) g.put(body, body.w - SIDE - 1, y, "│", "c-ad");
            flow(g, { x: body.x, y: body.y, w: body.w - SIDE - 1, h: body.h }, t, s);
            side(g, { x: body.x + body.w - SIDE, y: body.y, w: SIDE, h: body.h }, t, s);
        } else {
            var jh = Math.max(4, Math.min(8, Math.floor(body.h / 3)));
            flow(g, { x: body.x, y: body.y, w: body.w, h: body.h - jh - 2 }, t, s);
            memoryLine(g, { x: body.x, y: body.y + body.h - jh - 2, w: body.w, h: 1 }, t);
            journalCompact(g, { x: body.x, y: body.y + body.h - jh, w: body.w, h: jh }, t, s);
        }

        // app.rs render_footer, dashboard keys
        g.put(full, 0, rows - 1, " 1-6 screens  Tab cycle  m motion  r  ?  q ", "c-mu");
        var right = " daemon ● ", off = s.motion ? "" : " motion off ";
        var rx = cols - right.length - off.length;
        if (off) g.put(full, rx, rows - 1, off, "c-mu");
        g.put(full, rx + off.length, rows - 1, right, "c-ok");
        return g;
    }

    // ── the player ────────────────────────────────────────────────────────

    function chapterAt(t) {
        var c = 0;
        CHAPTERS.forEach(function (ch, i) { if (t >= ch[0]) c = i; });
        return c;
    }

    function init() {
        var prev = window.__soliTui;
        if (prev) prev.stop();
        window.__soliTui = null;

        var root = document.getElementById("tui");
        if (!root) return;
        var screen = root.querySelector(".term-screen");
        var pre = screen.querySelector("pre");
        var probe = screen.querySelector(".term-probe");
        var chapters = Array.prototype.slice.call(document.querySelectorAll("[data-chapter]"));
        var status = document.getElementById("tui-status");
        var toggle = document.getElementById("tui-motion");

        var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
        var s = {
            version: root.dataset.version || "",
            motion: !reduce.matches,
        };
        var t = CHAPTERS[0][0], cols = 0, visible = true, raf = 0, last = 0, lastFrame = -1, html = "";

        function measure() {
            var cw = probe.getBoundingClientRect().width / 10;
            if (!cw) return;
            cols = Math.max(40, Math.min(160, Math.floor(screen.clientWidth / cw)));
        }

        function paint() {
            if (!cols) return;
            var next = draw(cols, t, s).html();
            if (next !== html) { pre.innerHTML = next; html = next; }
            var c = chapterAt(t);
            chapters.forEach(function (el, i) {
                if (i === c) el.setAttribute("aria-current", "step");
                else el.removeAttribute("aria-current");
            });
            if (status) status.textContent = pad2(c + 1) + "/" + pad2(CHAPTERS.length) + " · " + (chapters[c] ? chapters[c].dataset.title : "");
            if (toggle) {
                toggle.setAttribute("aria-pressed", String(s.motion));
                toggle.querySelector("[data-state]").textContent = s.motion ? "on" : "off";
            }
        }

        function frame(now) {
            raf = 0;
            if (!root.isConnected) return stop();
            if (last) t = (t + Math.min(0.1, (now - last) / 1000)) % LOOP;
            last = now;
            var f = Math.floor(t / TICK);
            if (f !== lastFrame) { lastFrame = f; paint(); }
            schedule();
        }

        function schedule() {
            if (!raf && s.motion && visible && !document.hidden) raf = requestAnimationFrame(frame);
        }

        function halt() {
            if (raf) cancelAnimationFrame(raf);
            raf = 0;
            last = 0;
        }

        function seek(i) {
            t = s.motion ? CHAPTERS[i][0] : CHAPTERS[i][1];
            paint();
        }

        function setMotion(on) {
            s.motion = on;
            halt();
            // Still: show the chapter's telling moment rather than wherever
            // the loop happened to be.
            if (!on) t = CHAPTERS[chapterAt(t)][1];
            paint();
            schedule();
        }

        var onSeek = function (e) {
            var b = e.target.closest("[data-seek]");
            if (b) seek(Number(b.dataset.seek));
        };
        var onToggle = function () { setMotion(!s.motion); };
        var onKey = function (e) {
            if (e.key === "m" && !e.ctrlKey && !e.metaKey && !e.altKey) { setMotion(!s.motion); e.preventDefault(); }
        };
        var onVisibility = function () { if (document.hidden) halt(); else schedule(); };
        var onReduce = function () { setMotion(!reduce.matches); };

        var io = new IntersectionObserver(function (entries) {
            visible = entries[0].isIntersecting;
            if (visible) schedule(); else halt();
        });
        var ro = new ResizeObserver(function () { measure(); html = ""; paint(); });

        document.addEventListener("click", onSeek);
        if (toggle) toggle.addEventListener("click", onToggle);
        root.addEventListener("keydown", onKey);
        document.addEventListener("visibilitychange", onVisibility);
        reduce.addEventListener("change", onReduce);
        io.observe(root);
        ro.observe(screen);

        function stop() {
            halt();
            io.disconnect();
            ro.disconnect();
            document.removeEventListener("click", onSeek);
            if (toggle) toggle.removeEventListener("click", onToggle);
            root.removeEventListener("keydown", onKey);
            document.removeEventListener("visibilitychange", onVisibility);
            reduce.removeEventListener("change", onReduce);
        }
        window.__soliTui = { stop: stop };

        if (!s.motion) t = CHAPTERS[0][1];
        measure();
        paint();
        schedule();
        // Geist Mono may land after the first paint and change the cell width.
        if (document.fonts) document.fonts.ready.then(function () { if (root.isConnected) { measure(); html = ""; paint(); } });
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
    document.addEventListener("soli:load", init);
})();
