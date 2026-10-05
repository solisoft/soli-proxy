//! Response compression on a large HTML page, the case that matters: a
//! multi-megabyte server-rendered page, compressed by the proxy on its way
//! out.
//!
//! Three shapes of the same body:
//! - `full`: one frame, as a buffered backend or a static file hands it over;
//! - `frames_ready`: 16 KiB frames, all available at once;
//! - `frames_trickle`: 16 KiB frames with the backend `Pending` before each,
//!   which is what a body read off a socket looks like — data arrives a read
//!   at a time, and the backend has "nothing more for now" between reads.
//!
//! Prints the compressed size of each case once, so a change that buys speed
//! with ratio shows up. The page is a generated 4 MiB catalogue, or the file
//! named by `SOLI_BENCH_HTML`:
//!
//! ```sh
//! SOLI_BENCH_HTML=spec.html cargo bench --bench compression
//! ```

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response};
use soli_proxy::pool::BoxError;
use soli_proxy::response::compress::{apply, Coding, CompressionConfig, Requested};
use std::pin::Pin;
use std::task::{Context, Poll};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

const FRAME: usize = 16 * 1024;

/// A server-rendered catalogue page: repetitive markup with varying text and
/// numbers, which is what makes HTML compress 5–10× and costs the compressor
/// real work (a constant string would be unrealistically cheap).
fn big_html(target: usize) -> Bytes {
    const WORDS: &[&str] = &[
        "oak",
        "walnut",
        "linen",
        "copper",
        "table",
        "chair",
        "lamp",
        "shelf",
        "rustic",
        "modern",
        "hand-made",
        "vintage",
        "solid",
        "brushed",
        "natural",
        "black",
        "white",
        "small",
        "large",
        "set",
    ];
    let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut s = String::with_capacity(target + 4096);
    s.push_str(
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><title>Catalogue</title>",
    );
    s.push_str("<link rel=\"stylesheet\" href=\"/assets/app-3f2a9c.css\"></head><body><main class=\"container\"><table class=\"table table-striped\"><tbody>\n");
    let mut i = 0u64;
    while s.len() < target {
        let r = next();
        let name: Vec<&str> = (0..3)
            .map(|k| WORDS[((r >> (k * 8)) % WORDS.len() as u64) as usize])
            .collect();
        s.push_str(&format!(
            "<tr class=\"row\" data-id=\"{id}\"><td class=\"sku\">SKU-{sku:08}</td>\
             <td><a href=\"/products/{id}-{slug}\" class=\"product-link\">{title}</a></td>\
             <td class=\"price\">{euros},{cents:02}&nbsp;&euro;</td><td class=\"stock\">{stock} en stock</td>\
             <td><button type=\"button\" class=\"btn btn-sm btn-primary\" data-action=\"cart#add\" data-product=\"{id}\">Ajouter</button></td></tr>\n",
            id = 10_000 + i,
            sku = r % 100_000_000,
            slug = name.join("-"),
            title = name.join(" "),
            euros = (r >> 20) % 900 + 10,
            cents = (r >> 40) % 100,
            stock = (r >> 50) % 40,
        ));
        i += 1;
    }
    s.push_str("</tbody></table></main></body></html>\n");
    Bytes::from(s)
}

/// Hands out `frames`, returning `Pending` (and waking itself) before each
/// one when `trickle` is set.
struct Frames {
    frames: Vec<Bytes>,
    next: usize,
    trickle: bool,
    ready: bool,
}

impl Body for Frames {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.next == self.frames.len() {
            return Poll::Ready(None);
        }
        if self.trickle && !self.ready {
            self.ready = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.ready = false;
        let frame = self.frames[self.next].clone();
        self.next += 1;
        Poll::Ready(Some(Ok(Frame::data(frame))))
    }
}

fn body(html: &Bytes, shape: &str) -> BoxBody {
    match shape {
        "full" => Full::new(html.clone()).map_err(|e| match e {}).boxed(),
        _ => Frames {
            frames: html.chunks(FRAME).map(|c| html.slice_ref(c)).collect(),
            next: 0,
            trickle: shape == "frames_trickle",
            ready: false,
        }
        .boxed(),
    }
}

fn response(html: &Bytes, shape: &str) -> Response<BoxBody> {
    let mut resp = Response::new(body(html, shape));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

fn requested(coding: Coding, config: &CompressionConfig) -> Requested {
    let req = Request::builder()
        .header(header::ACCEPT_ENCODING, coding.token())
        .body(())
        .unwrap();
    Requested::capture(&req, config)
}

fn compress(
    rt: &tokio::runtime::Runtime,
    html: &Bytes,
    shape: &str,
    req: Requested,
    config: &CompressionConfig,
) -> usize {
    rt.block_on(async {
        let resp = apply(response(html, shape), req, config);
        let mut body = resp.into_body();
        let mut total = 0;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.unwrap().into_data() {
                total += data.len();
            }
        }
        total
    })
}

fn bench_compression(c: &mut Criterion) {
    // Timers on: the compressed body arms one when the backend pauses.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // `SOLI_BENCH_HTML=page.html` measures a real page instead.
    let html = match std::env::var("SOLI_BENCH_HTML") {
        Ok(path) => Bytes::from(std::fs::read(&path).expect("SOLI_BENCH_HTML")),
        Err(_) => big_html(4 * 1024 * 1024),
    };
    let mut config = CompressionConfig::default();
    config.enabled = true;
    config.algorithms = vec![Coding::Gzip, Coding::Brotli, Coding::Zstd];
    let config = config.validated().unwrap();

    let mut group = c.benchmark_group("compress_html");
    group.throughput(Throughput::Bytes(html.len() as u64));
    group.sample_size(10);
    for coding in [Coding::Gzip, Coding::Brotli, Coding::Zstd] {
        let req = requested(coding, &config);
        for shape in ["full", "frames_ready", "frames_trickle"] {
            let size = compress(&rt, &html, shape, req, &config);
            eprintln!(
                "{:>6} {:<14} {:>9} -> {:>8} bytes ({:.2}x)",
                coding.token(),
                shape,
                html.len(),
                size,
                html.len() as f64 / size as f64
            );
            group.bench_with_input(
                BenchmarkId::new(coding.token(), shape),
                &shape,
                |b, shape| b.iter(|| compress(&rt, &html, shape, req, &config)),
            );
        }
    }
    group.finish();

    // The level trade-off on the same page, one frame: what each step of
    // `gzip_level` / `brotli_level` / `zstd_level` costs and buys.
    let mut group = c.benchmark_group("levels_html");
    group.throughput(Throughput::Bytes(html.len() as u64));
    group.sample_size(10);
    let levels: [(Coding, &[i32]); 3] = [
        (Coding::Gzip, &[1, 3, 5, 6]),
        (Coding::Brotli, &[1, 2, 3, 4, 5]),
        (Coding::Zstd, &[1, 3, 6]),
    ];
    for (coding, list) in levels {
        let req = requested(coding, &config);
        for &level in list {
            let mut leveled = config.clone();
            match coding {
                Coding::Gzip => leveled.gzip_level = level as u32,
                Coding::Brotli => leveled.brotli_level = level as u32,
                Coding::Zstd => leveled.zstd_level = level,
            }
            let size = compress(&rt, &html, "full", req, &leveled);
            eprintln!(
                "{:>6} level {:<2} -> {:>8} bytes ({:.2}x)",
                coding.token(),
                level,
                size,
                html.len() as f64 / size as f64
            );
            group.bench_with_input(
                BenchmarkId::new(coding.token(), level),
                &leveled,
                |b, leveled| b.iter(|| compress(&rt, &html, "full", req, leveled)),
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_compression);
criterion_main!(benches);
