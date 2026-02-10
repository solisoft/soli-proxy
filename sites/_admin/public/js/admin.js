// Soli Proxy Admin API Client
// Connects to the proxy admin API (separate port)

var AdminAPI = (function() {
    // Auto-detect admin API base URL
    // The admin API runs on a different port than the Soli app
    // Default: same host, port 9090
    var _baseUrl = '';

    function _detectBaseUrl() {
        // Check for a configured override
        var el = document.getElementById('admin-api-url');
        if (el && el.value) return el.value;

        // Try localStorage
        var stored = localStorage.getItem('admin_api_url');
        if (stored) return stored;

        // Default: same host, port 9090
        var host = window.location.hostname || 'localhost';
        return 'http://' + host + ':9090';
    }

    _baseUrl = _detectBaseUrl();

    // ---- HTTP helpers ----

    function _fetch(path, options) {
        options = options || {};
        var url = _baseUrl + path;
        var headers = options.headers || {};
        var apiKey = localStorage.getItem('admin_api_key');
        if (apiKey) headers['X-Api-Key'] = apiKey;

        return fetch(url, {
            method: options.method || 'GET',
            headers: headers,
            body: options.body
        }).then(function(res) {
            if (res.status === 204) return {ok: true, data: null};
            var contentType = res.headers.get('content-type') || '';
            if (contentType.indexOf('text/plain') !== -1) {
                return res.text();
            }
            return res.json().then(function(data) {
                if (!res.ok) throw new Error(data.error || 'Request failed');
                return data;
            });
        });
    }

    function _post(path, body) {
        return _fetch(path, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: body ? JSON.stringify(body) : undefined
        });
    }

    function _put(path, body) {
        return _fetch(path, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
    }

    function _del(path) {
        return _fetch(path, {method: 'DELETE'});
    }

    // ---- API Methods ----

    function getStatus() { return _fetch('/api/v1/status'); }
    function getConfig() { return _fetch('/api/v1/config'); }
    function getRoutes() { return _fetch('/api/v1/routes'); }
    function getRoute(index) { return _fetch('/api/v1/routes/' + index); }
    function getMetrics() { return _fetch('/api/v1/metrics'); }
    function getCircuitBreaker() { return _fetch('/api/v1/circuit-breaker'); }
    function getApps() { return _fetch('/api/v1/apps'); }
    function getApp(name) { return _fetch('/api/v1/apps/' + encodeURIComponent(name)); }
    function getAppLogs(name) { return _fetch('/api/v1/apps/' + encodeURIComponent(name) + '/logs'); }

    function addRoute(route) { return _post('/api/v1/routes', route); }
    function updateRoute(index, route) { return _put('/api/v1/routes/' + index, route); }
    function deleteRoute(index) { return _del('/api/v1/routes/' + index); }

    function reloadConfig() { return _post('/api/v1/reload'); }
    function resetCircuitBreaker() { return _post('/api/v1/circuit-breaker/reset'); }

    function appAction(name, action) {
        return _post('/api/v1/apps/' + encodeURIComponent(name) + '/' + action);
    }

    function getAllAppMetrics() { return _fetch('/api/v1/app-metrics'); }

    function setBaseUrl(url) {
        _baseUrl = url;
        localStorage.setItem('admin_api_url', url);
    }

    // ---- Prometheus Parser ----
    // Parses Prometheus text format into { metricName: { labels: value } }

    function parsePrometheus(text) {
        var result = {};
        if (typeof text !== 'string') return result;

        text.split('\n').forEach(function(line) {
            line = line.trim();
            if (!line || line.charAt(0) === '#') return;

            var match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(.+)$/);
            if (!match) return;

            var name = match[1];
            var labels = match[2] || '';
            var value = parseFloat(match[3]);

            if (!result[name]) result[name] = {};
            result[name][labels] = value;
        });

        return result;
    }

    // ---- Format Helpers ----

    function formatUptime(secs) {
        if (!secs && secs !== 0) return '-';
        var d = Math.floor(secs / 86400);
        var h = Math.floor((secs % 86400) / 3600);
        var m = Math.floor((secs % 3600) / 60);
        var s = secs % 60;
        if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
        if (h > 0) return h + 'h ' + m + 'm ' + s + 's';
        if (m > 0) return m + 'm ' + s + 's';
        return s + 's';
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        if (i >= units.length) i = units.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
    }

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    // Get a single metric value (sum all label variants)
    function metricVal(parsed, name) {
        if (!parsed[name]) return 0;
        var vals = Object.values(parsed[name]);
        if (vals.length === 0) return 0;
        if (vals.length === 1) return vals[0];
        return vals.reduce(function(a, b) { return a + b; }, 0);
    }

    function esc(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ---- Toast Notifications ----

    function toast(message, type) {
        var container = document.getElementById('toast-container');
        if (!container) return;

        var colors = {
            success: 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400',
            error: 'bg-rose-500/20 border-rose-500/30 text-rose-400',
            info: 'bg-indigo-500/20 border-indigo-500/30 text-indigo-400'
        };

        var el = document.createElement('div');
        el.className = 'px-4 py-3 rounded-xl border text-sm font-medium shadow-lg backdrop-blur-sm animate-slide-in ' + (colors[type] || colors.info);
        el.textContent = message;
        container.appendChild(el);

        setTimeout(function() {
            el.style.opacity = '0';
            el.style.transform = 'translateX(100%)';
            el.style.transition = 'all 0.3s ease';
            setTimeout(function() { el.remove(); }, 300);
        }, 3000);
    }

    // ---- Loading Button State ----

    function setButtonLoading(btn, loading, originalText) {
        if (!btn) return;
        if (loading) {
            btn._originalText = btn.innerHTML;
            btn._originalDisabled = btn.disabled;
            btn.disabled = true;
            var text = btn.dataset.loadingText || 'Loading...';
            btn.innerHTML = '<span class="flex items-center justify-center gap-2"><svg class="animate-spin h-4 w-4" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>' + text + '</span>';
            btn.classList.add('opacity-75', 'cursor-not-allowed', 'whitespace-nowrap');
        } else {
            btn.disabled = btn._originalDisabled !== undefined ? btn._originalDisabled : false;
            btn.innerHTML = btn._originalText || btn.innerHTML;
            btn.classList.remove('opacity-75', 'cursor-not-allowed', 'whitespace-nowrap');
        }
    }

    // Find button by name and action and set loading
    function setActionButtonLoading(name, action, loading) {
        var btn = document.querySelector('[data-app="' + esc(name) + '"][data-action="' + esc(action) + '"]');
        if (btn) {
            setButtonLoading(btn, loading);
        }
    }

    // ---- Modal System ----

    function showModal(html) {
        var backdrop = document.getElementById('modal-backdrop');
        var container = document.getElementById('modal-container');
        var content = document.getElementById('modal-content');

        content.innerHTML = html;
        backdrop.classList.remove('hidden');
        container.classList.remove('hidden');

        backdrop.onclick = closeModal;
    }

    function closeModal() {
        document.getElementById('modal-backdrop').classList.add('hidden');
        document.getElementById('modal-container').classList.add('hidden');
    }

    // ---- Connection Banner ----

    function _showConnectionBanner() {
        var existing = document.getElementById('connection-banner');
        if (existing) return;
        var main = document.querySelector('main .p-6');
        if (!main) return;
        var banner = document.createElement('div');
        banner.id = 'connection-banner';
        banner.className = 'mb-6 p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-sm';
        banner.innerHTML = '<div class="flex items-start gap-3">' +
            '<svg class="w-5 h-5 text-amber-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z" /></svg>' +
            '<div class="flex-1">' +
                '<div class="font-medium text-amber-400 mb-1">Cannot reach Admin API</div>' +
                '<div class="text-slate-400 mb-3">Make sure the proxy is running and the admin API is enabled. Current target: <code class="text-xs bg-slate-800 px-1.5 py-0.5 rounded font-mono">' + esc(_baseUrl) + '</code></div>' +
                '<div class="flex items-center gap-2">' +
                    '<input id="api-url-input" type="text" value="' + esc(_baseUrl) + '" placeholder="http://localhost:9090" class="flex-1 bg-slate-800 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-amber-500/50">' +
                    '<button onclick="AdminAPI.setBaseUrl(document.getElementById(\'api-url-input\').value);location.reload();" class="px-3 py-1.5 bg-amber-500 hover:bg-amber-600 text-white text-xs font-medium rounded-lg transition-colors">Connect</button>' +
                '</div>' +
            '</div></div>';
        main.insertBefore(banner, main.firstChild);
    }

    function _hideConnectionBanner() {
        var el = document.getElementById('connection-banner');
        if (el) el.remove();
    }

    // ---- Initial Status Check (deferred to DOMContentLoaded) ----

    function _initCheck() {
        getStatus().then(function(d) {
            var s = d.data;
            _hideConnectionBanner();
            var versionEl = document.getElementById('sidebar-version');
            if (versionEl) versionEl.textContent = 'v' + s.version;
            var uptimeEl = document.getElementById('sidebar-uptime');
            if (uptimeEl) uptimeEl.textContent = 'Up ' + formatUptime(s.uptime_secs);
            var topVersionEl = document.getElementById('topbar-version');
            if (topVersionEl) topVersionEl.textContent = 'v' + s.version;
        }).catch(function() {
            _showConnectionBanner();
            var statusEl = document.getElementById('topbar-status');
            if (statusEl) {
                statusEl.className = 'hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20';
                statusEl.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-rose-400"></span> Disconnected';
            }
            var uptimeEl = document.getElementById('sidebar-uptime');
            if (uptimeEl) uptimeEl.textContent = 'Disconnected';
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _initCheck);
    } else {
        _initCheck();
    }

    // ---- Public API ----

    return {
        getStatus: getStatus,
        getConfig: getConfig,
        getRoutes: getRoutes,
        getRoute: getRoute,
        getMetrics: getMetrics,
        getCircuitBreaker: getCircuitBreaker,
        getApps: getApps,
        getApp: getApp,
        getAppLogs: getAppLogs,
        getAllAppMetrics: getAllAppMetrics,
        addRoute: addRoute,
        updateRoute: updateRoute,
        deleteRoute: deleteRoute,
        reloadConfig: reloadConfig,
        resetCircuitBreaker: resetCircuitBreaker,
        appAction: appAction,
        setBaseUrl: setBaseUrl,
        parsePrometheus: parsePrometheus,
        metricVal: metricVal,
        formatUptime: formatUptime,
        formatBytes: formatBytes,
        formatNumber: formatNumber,
        esc: esc,
        toast: toast,
        showModal: showModal,
        closeModal: closeModal,
        setButtonLoading: setButtonLoading,
        setActionButtonLoading: setActionButtonLoading
    };
})();
