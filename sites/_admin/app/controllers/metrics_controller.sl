class MetricsController extends Controller {
    fn index(req: Any) -> Any {
        return render("metrics/index", {
            "title": "Metrics",
            "current_page": "metrics"
        });
    }
}
