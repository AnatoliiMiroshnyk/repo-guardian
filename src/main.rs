use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir, trace::TraceLayer};
use tracing::{info, warn};

mod scanner;
use scanner::{scan_repository, ScanReport};

#[derive(Clone)]
struct AppState {
    max_files: usize,
}

#[derive(Deserialize)]
struct ScanRequest {
    path: String,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
    hint: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            env::var("RUST_LOG").unwrap_or_else(|_| "repo_guardian=info,tower_http=info".into()),
        )
        .init();

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8787);
    let max_files = env::var("MAX_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000usize);

    // Do not expose a filesystem-scanning service on a public interface by accident.
    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        warn!("HOST is not loopback; this app can inspect local files. Use loopback unless you understand the risk.");
    }

    let state = Arc::new(AppState { max_files });
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/scan", post(scan))
        .fallback_service(ServeDir::new("web").append_index_html_on_directories(true))
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .expect("HOST and PORT must form a valid socket address");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("failed to bind");
    info!("Repo Guardian available at http://{addr}");
    axum::serve(listener, app).await.expect("server failed");
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "repo-guardian" }))
}

async fn scan(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<ScanReport>, (StatusCode, Json<ApiError>)> {
    let raw = payload.path.trim();
    if raw.is_empty() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Path is required", "Enter an absolute path to a repository."));
    }
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Path must be absolute", "Use an absolute local directory path."));
    }
    let canonical = path.canonicalize().map_err(|_| {
        api_error(StatusCode::BAD_REQUEST, "Directory not found", "Check that the path exists and is accessible.")
    })?;
    if !canonical.is_dir() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Path is not a directory", "Select a repository directory."));
    }

    let report = tokio::task::spawn_blocking(move || scan_repository(&canonical, state.max_files))
        .await
        .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Scan worker failed", "Check logs and retry."))?
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, "Could not scan directory", &e))?;

    Ok(Json(report))
}

fn api_error(status: StatusCode, error: &str, hint: &str) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: error.into(), hint: hint.into() }))
}
