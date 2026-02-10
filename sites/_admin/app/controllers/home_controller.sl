class HomeController extends Controller {
    fn index(req: Any) -> Any {
        return render("home/index", {
            "title": "Dashboard",
            "current_page": "dashboard"
        });
    }

    fn health(req: Any) -> Any {
        return {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": "{\"status\":\"ok\"}"
        };
    }
}
