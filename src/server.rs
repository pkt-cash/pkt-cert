use std::{net::SocketAddr, sync::Arc};

use tokio::sync::Mutex;

use crate::config::Config;

pub struct ServerMut {
    // Map from token to key authorization
    pub challenges: std::collections::HashMap<String, String>,
}

pub struct Server {
    pub m: Mutex<ServerMut>,
    pub config: Config,
    pub bind: SocketAddr,
}

pub async fn warp_task(server: Arc<Server>) {
    use warp::Filter;

    let server1 = server.clone();
    let challenge_route =
        warp::path(".well-known".to_string())
        .and(warp::path("acme-challenge".to_string()))
        .and(warp::path::param())
        .and_then(move |token: String| {
            let server = server1.clone();
            async move {
                let m = server.m.lock().await;
                if let Some(key_auth) = m.challenges.get(&token) {
                    // println!("GET /.well-known/acme-challenge/{} -> OK", token);
                    Ok::<_, warp::Rejection>(warp::reply::with_status(
                        key_auth.clone(),
                        warp::http::StatusCode::OK,
                    ))
                } else {
                    Err(warp::reject::not_found())
                }
            }
        });

    warp::serve(challenge_route)
        .run(server.bind.clone())
        .await;
}
