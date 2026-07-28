class ChangelogController extends Controller {
    fn index(req: Any) -> Any {
        return render("changelog/index", {
            "title": "Changelog",
            "current_page": "changelog"
        });
    }
}
