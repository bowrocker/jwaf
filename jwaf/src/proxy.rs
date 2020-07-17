use futures::TryStreamExt;
use hyper::{server::Server, service, Body, Client, Request, Response, StatusCode};
use lazy_static::lazy_static;
use regex::Regex;
use slog::{crit, debug, info, o, Drain, Logger};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

// Note: this regular expression is used to search the input JSON for the is_malicious
// pattern. If more time were available, and Rust supported tail call elimination, it would be
// preferable to implement a recursive solution for searching an hierarchical JSON attachement.
lazy_static! {
    static ref RE: Regex = Regex::new(r#"\s?is_malicious\s?":true"#).unwrap();
}

// The address:port of the proxy should be configurable
// but for purposes of this exercise it's left out.
const PROXY_ADDR: &str = "127.0.0.1:3000";

// The main async function entry point for the proxy. The proxy is passed in as a configuration
// on the command line. The URL is re-assembled using the proxy and the passed in path from the
// http client, if the result is found not to be malicious and passed on.
pub async fn filter(
    proxy: &str,
    req: Request<Body>,
    log: &Logger,
) -> Result<Response<Body>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let path = parts.uri;

    let full_body = get_body(body).await;

    let json = full_body.map(|body| {
        // in a production environment this should return an HTTP error code such as 403/412.
        let json: serde_json::Value = serde_json::from_str(&String::from_utf8(body).unwrap())
            .expect("malformed JSON document");
        json
    })?;
    let json_body = json.to_string();
    debug!(log, "BODY: {}", json_body);
    if malicious_intent(&json_body) {
        // we got a live one, send back a 403
        crit!(
            log,
            "detected malicious request, returning a 403: {}",
            json.to_string()
        );
        return_forbidden()
    } else {
        // content looks innocent, send it along to the protected server
        // NB this does not copy over headers; it should
        let proxy_req = Request::builder()
            .method(parts.method)
            .uri(format!("{}{}", &proxy, path))
            .body(Body::from(json_body))
            .expect("Failed to build request for proxy");
        proxy_request(proxy_req, log).await
    }
}
// Retrive the body from the request in its entirety.
async fn get_body(body: Body) -> Result<Vec<u8>, hyper::Error> {
    body.try_fold(Vec::new(), |mut data, chunk| async move {
        data.extend_from_slice(&chunk);
        Ok(data)
    })
    .await
}

// Create a 403 response in the case of a malicious request.
fn return_forbidden() -> Result<Response<Body>, hyper::Error> {
    let mut forbidden = Response::default();
    *forbidden.status_mut() = StatusCode::FORBIDDEN;
    Ok(forbidden)
}

// Do the proxy on the assembled URI and return the Response.
async fn proxy_request(req: Request<Body>, log: &Logger) -> Result<Response<Body>, hyper::Error> {
    info!(
        log,
        "request appears non-malicious, forwarding to {}",
        req.uri()
    );
    let client = Client::new();
    let r = client.request(req).await?;
    Ok(r)
}

// Use the statically compiled regex to search the entire JSON attachment for the 'is_malicious`
// key.
fn malicious_intent(suspicious: &str) -> bool {
    RE.is_match(suspicious)
}

// Kick off an async-based Hyper http server to accept incoming requests, filter them
// and possibly proxy requests to another http server, sent in on the command line.
pub async fn start_server(proxy_addr: String) {
    // set up logging
    let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let log = Logger::root(
        Mutex::new(slog_term::FullFormat::new(plain).build()).fuse(),
        o!("build-id" => "0.1.0"),
    );

    let addr = PROXY_ADDR.parse().expect("Invalid address");
    let dupe_cache: HashMap<String, String> = HashMap::new();
    let dupe_cache = std::sync::RwLock::new(dupe_cache);

    // Need an Arc and 2 clones here to pass safely to the closures below for thread
    // sharing safety.
    let proxy = Arc::new(proxy_addr.to_string());
    let dupe = Arc::new(dupe_cache);
    let loga = Arc::new(log);

    let make_svc = service::make_service_fn(|_| {
        let proxy1 = Arc::clone(&proxy);
        let dupe1 = Arc::clone(&dupe);
        let log1 = Arc::clone(&loga);
        async move {
            Ok::<_, Infallible>(service::service_fn(move |req: Request<Body>| {
                let proxy2 = Arc::clone(&proxy1);
                let log2 = Arc::clone(&log1);
                let mut dc = dupe1.write().unwrap();
                if let Some(met) = dc.get(&req.uri().to_string()) {
                    if *met == req.method().to_string() {
                        crit!(
                            &*log2,
                            "duplicate request, uri:{} method:{}",
                            req.uri().to_string(),
                            *met
                        );
                    }
                }
                dc.insert(req.uri().to_string(), req.method().to_string());
                async move { filter(&*proxy2, req, &*log2).await }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("Error: {}", e);
    }
}
