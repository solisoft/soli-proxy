class DocsController extends Controller {
    fn getting_started(req) {
        render("docs/getting_started", {
            "title": "Getting Started"
        })
    }

    fn apps(req) {
        render("docs/apps", {
            "title": "Apps"
        })
    }

    fn configuration(req) {
        render("docs/configuration", {
            "title": "Configuration"
        })
    }

    fn admin_api(req) {
        render("docs/admin_api", {
            "title": "Admin API"
        })
    }

    fn scripting(req) {
        render("docs/scripting", {
            "title": "Scripting"
        })
    }

    fn security(req) {
        render("docs/security", {
            "title": "Security"
        })
    }

    fn deployment(req) {
        render("docs/deployment", {
            "title": "Deployment"
        })
    }

    fn benchmark(req) {
        render("docs/benchmark", {
            "title": "Benchmark"
        })
    }
}
