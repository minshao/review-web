pub mod archive;
pub mod auth;
pub mod graphql;

use crate::auth::{validate_token, AuthError};
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::{rejection::TypedHeaderRejection, Extension, TypedHeader},
    headers::authorization::{Authorization, Bearer},
    response::{Html, IntoResponse},
    routing::{get, get_service, post},
    Json, Router,
};
use graphql::AgentManager;
pub use graphql::CertManager;
use review_database::{Database, Store};
use rustls::{Certificate, ClientConfig, RootCertStore};
use serde_json::json;
use std::{
    fs::read,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{sync::Notify, task::JoinHandle};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::error;

/// Parameters for a web server.
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub document_root: PathBuf,
    pub cert_manager: Arc<dyn CertManager>,
    pub cert_reload_handle: Arc<Notify>,
    pub ca_certs: Vec<PathBuf>,
    pub reverse_proxies: Vec<archive::Config>,
}

/// Runs a web server.
pub async fn serve<A>(
    config: ServerConfig,
    db: Database,
    store: Arc<Store>,
    ip_locator: Option<Arc<Mutex<ip2location::DB>>>,
    agent_manager: A,
) -> Arc<Notify>
where
    A: AgentManager + 'static,
{
    use axum_server::{tls_rustls::RustlsConfig, Handle};
    use tracing::info;

    let schema = graphql::schema(
        db,
        store.clone(),
        agent_manager,
        ip_locator,
        config.cert_manager.clone(),
        config.cert_reload_handle.clone(),
    );
    let web_srv_shutdown_handle = Arc::new(Notify::new());
    let shutdown_handle = web_srv_shutdown_handle.clone();
    let client = client(&config.ca_certs);
    let server: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        loop {
            let static_files = get_service(ServeDir::new(config.document_root.clone()));

            let proxies_config = crate::archive::Config::configure_reverse_proxies(
                &store,
                &client,
                &config.reverse_proxies,
            );

            let mut router = Router::new()
                .route("/graphql", post(graphql_handler))
                .route(
                    "/graphql/playground",
                    get(graphql_playground).post(graphql_handler),
                )
                .fallback_service(static_files.layer(TraceLayer::new_for_http()))
                .layer(Extension(schema.clone()))
                .layer(Extension(store.clone()));
            for (s, p) in proxies_config {
                router = router.nest(&s.base(), p.with_state(s));
            }

            let handle = Handle::new();
            let notify_shutdown = Arc::new(Notify::new());
            let shutdown_completed = Arc::new(Notify::new());
            let (cert_path, key_path) = (
                config.cert_manager.cert_path()?,
                config.cert_manager.key_path()?,
            );
            let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

            let wait_shutdown = notify_shutdown.clone();
            let completed = shutdown_completed.clone();
            tokio::spawn(graceful_shutdown(handle.clone(), wait_shutdown));
            tokio::spawn(async move {
                axum_server::bind_rustls(config.addr, tls_config)
                    .handle(handle)
                    .serve(router.into_make_service())
                    .await
                    .unwrap();
                completed.notify_one();
            });

            let wait_shutdown = web_srv_shutdown_handle.notified();
            let cert_reload = config.cert_reload_handle.notified();

            tokio::select! {
                _ = wait_shutdown => {
                    info!("Shutting down Web server");
                    notify_shutdown.notify_one();
                    shutdown_completed.notified().await;
                    web_srv_shutdown_handle.notify_one();
                    return Ok(());
                },
                _ = cert_reload => {
                    info!("Restarting Web server to reload certificates");
                    notify_shutdown.notify_one();
                    shutdown_completed.notified().await;
                },
            }
        }
    });

    tracing::info!("Starting Web Server");
    tokio::spawn(async {
        match server.await {
            Ok(Err(e)) => error!("Web server died: {:?}", e),
            Err(e) => error!("Web server task failed to execute to completion: {:?}", e),
            _ => (),
        }
    });

    shutdown_handle
}

pub(crate) fn client<P: AsRef<std::path::Path>>(ca_certs: &[P]) -> Option<reqwest::Client> {
    let with_platform_root = false;
    let tls_config =
        build_client_config(ca_certs, with_platform_root).expect("failed to add cert to store");

    reqwest::ClientBuilder::new()
        .use_preconfigured_tls(tls_config)
        .build()
        .ok()
}

async fn graceful_shutdown(handle: axum_server::Handle, notify: Arc<Notify>) {
    use std::time::Duration;

    notify.notified().await;
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
}

#[allow(clippy::unused_async)]
async fn graphql_playground() -> Result<impl IntoResponse, Error> {
    Ok(Html(playground_source(GraphQLPlaygroundConfig::new(
        "/graphql",
    ))))
}

async fn graphql_handler(
    Extension(schema): Extension<graphql::Schema>,
    Extension(store): Extension<Arc<Store>>,
    auth: Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    request: GraphQLRequest,
) -> Result<GraphQLResponse, Error> {
    let request = request.into_inner();

    match auth {
        Ok(auth) => {
            let (username, role) = validate_token(&store, auth.token())?;
            Ok(schema
                .execute(request.data(username).data(role))
                .await
                .into())
        }
        Err(_e) => Ok(schema.execute(request).await.into()),
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Service Unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("With status: {0}")]
    WithStatus(reqwest::StatusCode),
    #[error("Time out: {0}")]
    TimeOut(String),
    #[error("Authentication Error: {0}")]
    Unauthorized(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("InternalServerError: {0}")]
    InternalServerError(String),
    #[error("Other: {0}")]
    Other(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use http::StatusCode;

        let (status, msg) = match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            Self::WithStatus(s) => (s, format!("Oops, {s}")),
            Self::TimeOut(msg) => (StatusCode::REQUEST_TIMEOUT, msg),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::NotFound(msg) | Self::Other(msg) => (StatusCode::NOT_FOUND, msg),
        };
        let body = Json(json!({
            "error": msg,
        }));
        (status, body).into_response()
    }
}

impl From<AuthError> for Error {
    fn from(err: AuthError) -> Self {
        Self::Unauthorized(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => Self::NotFound(err.to_string()),
            _ => Self::InternalServerError(err.to_string()),
        }
    }
}

impl From<TypedHeaderRejection> for Error {
    fn from(err: TypedHeaderRejection) -> Self {
        Self::Unauthorized(err.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_status() {
            Self::WithStatus(err.status().unwrap_or_default())
        } else if err.is_connect() {
            Self::ServiceUnavailable(err.to_string())
        } else if err.is_timeout() {
            Self::TimeOut(err.to_string())
        } else if err.is_request() {
            Self::BadRequest(err.to_string())
        } else {
            Self::Other(err.to_string())
        }
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::ServiceUnavailable(format!("Fail to route: {err}"))
    }
}

fn build_client_config<P: AsRef<Path>>(
    root_ca: &[P],
    with_platform_root: bool,
) -> Result<ClientConfig, anyhow::Error> {
    let mut root_store = RootCertStore::empty();
    if with_platform_root {
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    root_store.add(&rustls::Certificate(cert.0))?;
                }
            }
            Err(e) => tracing::error!("Could not load platform certificates: {:#}", e),
        }
    }
    for root in root_ca {
        let certs = read_certificate_from_path(root)?;
        for cert in certs {
            root_store.add(&cert)?;
        }
    }

    let mut builder = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    builder.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(builder)
}

fn read_certificate_from_path<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>, anyhow::Error> {
    let cert = read(&path)?;
    Ok(rustls_pemfile::certs(&mut &*cert)?
        .into_iter()
        .map(Certificate)
        .collect())
}
