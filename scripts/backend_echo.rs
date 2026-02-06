use std::net::SocketAddr;
use hyper::{Body, Request, Response};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let listener = TcpListener::bind(&addr).await?;
    
    println!("Backend echo server listening on {}", addr);
    
    loop {
        let (stream, _) = listener.accept().await?;
        
        tokio::spawn(async move {
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(stream, service_fn(echo))
                .await
            {
                eprintln!("Error serving connection: {}", e);
            }
        });
    }
}

async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path().to_string();
    let host = req.uri().host().unwrap_or("unknown");
    
    let response = format!("Backend received: {} from {}", path, host);
    
    Ok(Response::builder()
        .status(200)
        .body(Body::from(response))
        .unwrap())
}
