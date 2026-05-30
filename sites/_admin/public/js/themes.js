// Soli Proxy Admin — Theme presets
//
// Each preset defines a themeable `surface` (background) scale and an `accent`
// scale as space-separated RGB channels. ThemeManager applies a preset by
// writing these as CSS variables on <html>; Tailwind's surface-*/accent-*
// utilities (see tailwind.config.js) resolve against them.
//
// The selected preset is persisted server-side via the admin API
// (GET/PUT /api/v1/settings) so it is shared across browsers, and mirrored to
// localStorage so it can be applied before first paint (no flash).

var ThemeManager = (function() {
    var STORAGE_KEY = 'admin_theme';
    var DEFAULT_THEME = 'emerald';

    // Background scales (Tailwind palettes).
    var SURFACES = {
        slate:   { 200: '226 232 240', 300: '203 213 225', 400: '148 163 184', 500: '100 116 139', 600: '71 85 105',  700: '51 65 85',  800: '30 41 59',  900: '15 23 42',  950: '2 6 23'   },
        zinc:    { 200: '228 228 231', 300: '212 212 216', 400: '161 161 170', 500: '113 113 122', 600: '82 82 91',   700: '63 63 70',  800: '39 39 42',  900: '24 24 27',  950: '9 9 11'   },
        stone:   { 200: '231 229 228', 300: '214 211 209', 400: '168 162 158', 500: '120 113 108', 600: '87 83 78',   700: '68 64 60',  800: '41 37 36',  900: '28 25 23',  950: '12 10 9'  },
        gray:    { 200: '229 231 235', 300: '209 213 219', 400: '156 163 175', 500: '107 114 128', 600: '75 85 99',   700: '55 65 81',  800: '31 41 55',  900: '17 24 39',  950: '3 7 18'   }
    };

    // Accent scales (Tailwind palettes).
    var ACCENTS = {
        emerald: { 300: '110 231 183', 400: '52 211 153',  500: '16 185 129',  600: '5 150 105'  },
        sky:     { 300: '125 211 252', 400: '56 189 248',  500: '14 165 233',  600: '2 132 199'  },
        indigo:  { 300: '165 180 252', 400: '129 140 248', 500: '99 102 241',  600: '79 70 229'  },
        violet:  { 300: '196 181 253', 400: '167 139 250', 500: '139 92 246',  600: '124 58 237' },
        amber:   { 300: '252 211 77',  400: '251 191 36',  500: '245 158 11',  600: '217 119 6'  },
        rose:    { 300: '253 164 175', 400: '251 113 133', 500: '244 63 94',   600: '225 29 72'  }
    };

    // Built-in presets, in display order.
    var PRESETS = [
        { id: 'emerald', label: 'Emerald', desc: 'Cool slate · emerald accent', surface: 'slate', accent: 'emerald' },
        { id: 'ocean',   label: 'Ocean',   desc: 'Cool slate · sky accent',     surface: 'slate', accent: 'sky'     },
        { id: 'indigo',  label: 'Indigo',  desc: 'Cool slate · indigo accent',  surface: 'slate', accent: 'indigo'  },
        { id: 'violet',  label: 'Violet',  desc: 'Neutral zinc · violet accent', surface: 'zinc', accent: 'violet'  },
        { id: 'amber',   label: 'Amber',   desc: 'Warm stone · amber accent',   surface: 'stone', accent: 'amber'   },
        { id: 'rose',    label: 'Rose',    desc: 'Neutral zinc · rose accent',  surface: 'zinc',  accent: 'rose'    }
    ];

    var _byId = {};
    PRESETS.forEach(function(p) { _byId[p.id] = p; });

    function get(id) { return _byId[id] || _byId[DEFAULT_THEME]; }

    // Write a preset's CSS variables onto <html>.
    function apply(id) {
        var preset = get(id);
        var root = document.documentElement;
        var surface = SURFACES[preset.surface];
        var accent = ACCENTS[preset.accent];
        Object.keys(surface).forEach(function(shade) {
            root.style.setProperty('--surface-' + shade, surface[shade]);
        });
        Object.keys(accent).forEach(function(shade) {
            root.style.setProperty('--accent-' + shade, accent[shade]);
        });
        root.setAttribute('data-theme', preset.id);
    }

    // Apply the locally-cached preset immediately (called before paint).
    function applyCached() {
        var cached = null;
        try { cached = localStorage.getItem(STORAGE_KEY); } catch (e) {}
        apply(cached || DEFAULT_THEME);
    }

    // Persist a preset: cache locally, apply, and push to the server.
    function select(id) {
        if (!_byId[id]) return Promise.reject(new Error('Unknown theme: ' + id));
        try { localStorage.setItem(STORAGE_KEY, id); } catch (e) {}
        apply(id);
        if (typeof AdminAPI !== 'undefined' && AdminAPI.updateSettings) {
            return AdminAPI.updateSettings({ theme: id });
        }
        return Promise.resolve();
    }

    // Reconcile with the server-side setting (source of truth across browsers).
    function syncFromServer() {
        if (typeof AdminAPI === 'undefined' || !AdminAPI.getSettings) return;
        AdminAPI.getSettings().then(function(d) {
            var theme = d && d.data && d.data.theme;
            if (theme && _byId[theme]) {
                try { localStorage.setItem(STORAGE_KEY, theme); } catch (e) {}
                apply(theme);
                if (ThemeManager.onChange) ThemeManager.onChange(theme);
            }
        }).catch(function() { /* offline: keep cached theme */ });
    }

    function current() {
        var el = document.documentElement.getAttribute('data-theme');
        return el || DEFAULT_THEME;
    }

    // Preview colors for a preset (used to render swatches on the Settings page).
    function swatch(id) {
        var preset = get(id);
        var s = SURFACES[preset.surface];
        var a = ACCENTS[preset.accent];
        return {
            bg: 'rgb(' + s[950] + ')',
            panel: 'rgb(' + s[800] + ')',
            text: 'rgb(' + s[400] + ')',
            accent: 'rgb(' + a[500] + ')',
            accentSoft: 'rgb(' + a[400] + ')'
        };
    }

    // Apply cached theme as early as possible to avoid a flash of the default.
    applyCached();

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', syncFromServer);
    } else {
        syncFromServer();
    }

    return {
        PRESETS: PRESETS,
        DEFAULT_THEME: DEFAULT_THEME,
        apply: apply,
        select: select,
        current: current,
        get: get,
        swatch: swatch,
        syncFromServer: syncFromServer,
        onChange: null
    };
})();
