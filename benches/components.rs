use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soli_proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use soli_proxy::metrics::Metrics;
use soli_proxy::server::LoadBalancerState;
use std::time::Duration;

fn bench_circuit_breaker(c: &mut Criterion) {
    let mut group = c.benchmark_group("circuit_breaker");

    let config = CircuitBreakerConfig::default();
    let cb = CircuitBreaker::new(config);

    // Pre-register a target so the hot path has state
    cb.is_available("http://backend:8080");

    group.bench_function("is_available_closed", |b| {
        b.iter(|| cb.is_available(black_box("http://backend:8080")))
    });

    group.bench_function("record_success", |b| {
        b.iter(|| cb.record_success(black_box("http://backend:8080")))
    });

    group.bench_function("is_failure_status_match", |b| {
        b.iter(|| cb.is_failure_status(black_box(502)))
    });

    group.bench_function("is_failure_status_no_match", |b| {
        b.iter(|| cb.is_failure_status(black_box(200)))
    });

    // Scaling: check availability across many targets
    let config_scale = CircuitBreakerConfig::default();
    let cb_scale = CircuitBreaker::new(config_scale);
    for i in 0..1000 {
        cb_scale.is_available(&format!("http://backend{}:8080", i));
    }

    group.bench_function("is_available_1000_targets", |b| {
        b.iter(|| cb_scale.is_available(black_box("http://backend500:8080")))
    });

    group.finish();
}

fn bench_load_balancer(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_balancer");

    let lb = LoadBalancerState::new(10);

    group.bench_function("select_index_1_target", |b| {
        b.iter(|| lb.select_index(black_box(0), black_box(1)))
    });

    group.bench_function("select_index_3_targets", |b| {
        b.iter(|| lb.select_index(black_box(0), black_box(3)))
    });

    group.bench_function("select_index_10_targets", |b| {
        b.iter(|| lb.select_index(black_box(0), black_box(10)))
    });

    group.finish();
}

fn bench_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics");

    let metrics = Metrics::new();

    group.bench_function("record_request", |b| {
        b.iter(|| {
            metrics.record_request(
                black_box(1024),
                black_box(2048),
                black_box(200),
                black_box(Duration::from_micros(500)),
            )
        })
    });

    group.bench_function("inc_dec_in_flight", |b| {
        b.iter(|| {
            metrics.inc_in_flight();
            metrics.dec_in_flight();
        })
    });

    // Pre-populate metrics for format_metrics benchmark
    let metrics_populated = Metrics::new();
    for i in 0..1000 {
        metrics_populated.record_request(
            1024,
            2048,
            if i % 10 == 0 { 500 } else { 200 },
            Duration::from_micros(500),
        );
    }

    group.bench_function("format_metrics", |b| {
        b.iter(|| black_box(metrics_populated.format_metrics()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_circuit_breaker,
    bench_load_balancer,
    bench_metrics
);
criterion_main!(benches);
