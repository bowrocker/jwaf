## JWAF

Rust sample web appliction framework.

### platform

Tested with rust 1.44 on Mac OSX Mojave

### Requirements

Requirements taken from text in the original README. Duplicate requests for this exercise were taken to mean duplicate URI and HTTP method.

In addition, the proxy should be able perform at a minimum of 10 tx/sec.

### Running the tests

The integration tests bring up a test http server to proxy for and the tests run against it. That can be run with:

`cargo test -- --test-threads=1 --nocapture`

Manual testing was done by running the python simple server:

`% python -m SimpleHTTPServer 8000`

In the main directory, containing the index.html, and then running the proxy from cargo:

`cargo run jwaf --bin --s http::/localhost:8000`

And then curl commands (variable), like so:

`curl -i -d '{"is_malicious":"false", "key2":"value2", "foo":{"is_malicious": "false"}}' -H "Content-Type: application/json" -X GET http://localhost:3000`

