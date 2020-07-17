// Tests should be run via cargo with the following:
// % cargo test -- --test-threads=1
//
// The tests bring up http_test_servers as the protected resouces
// and send requests through the proxy

use jwaf::proxy::start_server;

#[cfg(test)]
mod tests {
    use super::*;
    use http_test_server::TestServer;
    use std::time;
    use time::Instant;
    use ureq::json;

    use tokio::runtime::Runtime;

    #[test]
    fn test_innocent_get_request() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/");

        resource
            .method(http_test_server::http::Method::GET)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"this is a message\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::get("http://127.0.0.1:3000").send_json(json!({
            "is_malicious": false
        }));

        assert!(resp.ok())
    }

    #[test]
    fn test_innocent_get_request_nested() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/");

        resource
            .method(http_test_server::http::Method::GET)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"this is a message\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::get("http://127.0.0.1:3000").send_json(json!(
            { "hidden": { "is_malicious": true } }
        ));

        assert!(resp.status() == 403)
    }

    #[test]
    fn test_innocent_get_path() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/sitting-duck");

        resource
            .method(http_test_server::http::Method::GET)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"this is a message\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::get("http://127.0.0.1:3000/sitting-duck").send_json(json!({
            "is_malicious": false
        }));

        assert!(resp.ok())
    }

    #[test]
    fn test_malicious_get_request() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/");

        resource
            .method(http_test_server::http::Method::GET)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"this is a message\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::get("http://127.0.0.1:3000").send_json(json!({
            "is_malicious": true
        }));
        assert!(resp.status() == 403);
    }

    #[test]
    fn test_malicious_post_request() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/");

        resource
            .method(http_test_server::http::Method::POST)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-cache")
            .body("{ \"message\": \"success\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::post("http://127.0.0.1:3000").send_json(json!({
            "is_malicious": true
        }));

        assert!(resp.status() == 403);
    }

    #[test]
    fn test_malicious_put_request() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/");

        resource
            .method(http_test_server::http::Method::PUT)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-cache")
            .body("{ \"message\": \"protected\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::post("http://127.0.0.1:3000").send_json(json!({
            "is_malicious": true
        }));

        assert!(resp.status() == 403);
    }

    #[test]
    fn test_innocent_put_request() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/putpath");

        resource
            .method(http_test_server::http::Method::PUT)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"protected\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let resp = ureq::put("http://127.0.0.1:3000/putpath").send_json(json!({
            "is_malicious": false
        }));

        assert!(resp.ok())
    }

    #[test]
    fn test_dupe_request() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/putpath");

        resource
            .method(http_test_server::http::Method::PUT)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"protected\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let _resp = ureq::put("http://127.0.0.1:3000/putpath").send_json(json!({
            "is_malicious": "false"
        }));
        let resp = ureq::put("http://127.0.0.1:3000/putpath").send_json(json!({
            "is_malicious": "false"
        }));

        assert!(resp.ok())
    }

    #[test]
    fn test_performance() {
        let server = TestServer::new().unwrap();
        let resource = server.create_resource("/path");

        resource
            .method(http_test_server::http::Method::GET)
            .header("Content-Type", "application/json")
            .body("{ \"message\": \"protected\" }");

        let rt = Runtime::new().unwrap();

        rt.spawn(start_server(
            format!("http://127.0.0.1:{}", server.port()).to_string(),
        ));

        let total_time = time::Duration::from_millis(1000);

        let instant = Instant::now();

        // run 200 GET requests through the proxy and assert it won't take more than
        // 1 second to complete.
        for _i in 0..150 {
            let resp = ureq::get("http://127.0.0.1:3000/path").send_json(json!({
                "is_malicious": "false"
            }));
            assert!(resp.ok());
        }
        println!("time elapsed for 200 requests: {:#?}", instant.elapsed());
        assert!(instant.elapsed() <= total_time)
    }
}
