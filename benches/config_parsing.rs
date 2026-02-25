use criterion::{criterion_group, criterion_main, Criterion};
use std::io::Write;
use tempfile::NamedTempFile;

fn make_config(rule_count: usize) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    for i in 0..rule_count {
        writeln!(file, "app{}.example.com -> http://backend{}:8080", i, i).unwrap();
    }
    writeln!(file, "default -> http://fallback:3000").unwrap();
    file.flush().unwrap();
    file
}

fn bench_config_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_parsing");

    let small_config = make_config(5);
    let small_path = small_config.path().to_str().unwrap().to_string();

    group.bench_function("parse_5_rules", |b| {
        b.iter(|| {
            let _ = soli_proxy::ConfigManager::new(&small_path).unwrap();
        })
    });

    let large_config = make_config(100);
    let large_path = large_config.path().to_str().unwrap().to_string();

    group.bench_function("parse_100_rules", |b| {
        b.iter(|| {
            let _ = soli_proxy::ConfigManager::new(&large_path).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_config_parsing);
criterion_main!(benches);
