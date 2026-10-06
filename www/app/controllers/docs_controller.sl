class DocsController extends Controller {
    fn getting_started(req) {
        render("docs/getting_started", {
            "title": "Getting Started",
            "description": "Install Soli Proxy, write a proxy.conf and serve your apps over HTTPS in minutes.",
            "path": "/docs/getting-started"
        })
    }

    fn apps(req) {
        render("docs/apps", {
            "title": "Apps",
            "description": "Host apps: app.infos, blue-green deploys, scale to zero, maintenance, per-site settings.",
            "path": "/docs/apps"
        })
    }

    fn configuration(req) {
        render("docs/configuration", {
            "title": "Configuration",
            "description": "Every config.toml section: TLS, limits, compression, error pages, maintenance, bots.",
            "path": "/docs/configuration"
        })
    }

    fn dev_https(req) {
        render("docs/dev_https", {
            "title": "Dev HTTPS & .test",
            "description": "Trusted local HTTPS on .test domains for development with Soli Proxy.",
            "path": "/docs/dev-https"
        })
    }

    fn admin_api(req) {
        render("docs/admin_api", {
            "title": "Admin API",
            "description": "The Soli Proxy admin API: routes, apps, deploys, metrics, maintenance and bans.",
            "path": "/docs/admin-api"
        })
    }

    fn scripting(req) {
        render("docs/scripting", {
            "title": "Scripting",
            "description": "Lua hooks in Soli Proxy: inspect, route, rewrite or deny requests and responses.",
            "path": "/docs/scripting"
        })
    }

    fn security(req) {
        render("docs/security", {
            "title": "Security",
            "description": "How Soli Proxy is hardened: trusted proxies, tenant isolation, admin access, limits.",
            "path": "/docs/security"
        })
    }

    fn deployment(req) {
        render("docs/deployment", {
            "title": "Deployment",
            "description": "Soli Proxy in production: systemd, upgrades without downtime, apps that survive restarts.",
            "path": "/docs/deployment"
        })
    }

    fn benchmark(req) {
        render("docs/benchmark", {
            "title": "Benchmark",
            "description": "Soli Proxy throughput and latency, measured, and how to reproduce the numbers.",
            "path": "/docs/benchmark"
        })
    }

    fn changelog(req) {
        render("docs/changelog", {
            "title": "Changelog",
            "description": "Release history of Soli Proxy: what changed in each version.",
            "path": "/changelog"
        })
    }
}
