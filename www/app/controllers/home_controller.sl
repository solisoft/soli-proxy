class HomeController extends Controller {
    fn index(req) {
        render("home/index", {
            "title": "HTTP/2 Reverse Proxy Server"
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
