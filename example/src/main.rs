use std::net::SocketAddr;
use axum::{middleware, Router, routing::get};
use firebase_jwt::axum::{axum_auth_middleware, AppState};
use anyhow::Result;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let app_state = AppState::new("your-project-id".to_string());

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Set up the server address
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server starting on {}", addr);


    let jwt_routes = Router::new()
        .route("/auth/example", get(auth))
        .layer(middleware::from_fn_with_state(app_state.expect("Unable to get app state").clone(), axum_auth_middleware));

    let app: Router = Router::new()
        .route("/", get(root))
        .merge(jwt_routes)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::debug!("listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn root() -> &'static str {
    "Hello World!"
}

async fn auth() -> &'static str {
    "Hello World with Auth!"
}