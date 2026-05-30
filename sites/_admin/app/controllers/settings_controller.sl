class SettingsController extends Controller {
    fn index(req: Any) -> Any {
        return render("settings/index", {
            "title": "Settings",
            "current_page": "settings"
        });
    }
}
