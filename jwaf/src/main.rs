// Copyright 2020, Jon Anderson
//
// This is a coding exercise for use in the interview process at ThreatX, Inc.
//
use jwaf::proxy::start_server;
use std::env;

#[tokio::main]
async fn main() {
    let arg: Vec<String> = env::args().collect();

    let proxy_url = &arg[1];

    start_server(proxy_url.to_string()).await;
}
