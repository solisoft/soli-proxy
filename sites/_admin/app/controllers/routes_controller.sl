class RoutesController extends Controller {
    fn index(req: Any) -> Any {
        return render("routes/index", {
            "title": "Routes",
            "current_page": "routes"
        });
    }
}
