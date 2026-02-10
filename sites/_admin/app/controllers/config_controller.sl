class ConfigController extends Controller {
    fn index(req: Any) -> Any {
        return render("config/index", {
            "title": "Configuration",
            "current_page": "config"
        });
    }
}
