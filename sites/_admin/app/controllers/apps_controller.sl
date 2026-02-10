class AppsController extends Controller {
    fn index(req: Any) -> Any {
        return render("apps/index", {
            "title": "Applications",
            "current_page": "apps"
        });
    }
}
