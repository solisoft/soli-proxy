class HomeController extends Controller {
    fn index(req) {
        render("home/index", {
            "title": "HTTP/2 Reverse Proxy Server",
            "description": "HTTP/2 reverse proxy in Rust: automatic TLS, blue-green deploys, scale to zero.",
            "path": "/"
        })
    }

    fn health(req) {
        render_json({
            "status": "ok"
        })
    }

    fn up(req) {
        render_text("UP")
    }
}
