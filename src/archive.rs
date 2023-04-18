use crate::{auth::validate_token, Error, Store};
use axum::{
    async_trait,
    body::{boxed, Body},
    extract::{rejection::TypedHeaderRejection, FromRef, FromRequestParts, Path, State},
    headers::{authorization::Bearer, Authorization},
    http::Request,
    middleware::{from_fn_with_state, Next},
    response::Response,
    routing::post,
    Router, TypedHeader,
};
use http::{request::Parts, StatusCode};
use review_database::types::Role;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    base: String,
    uri: String,
    roles: Option<Vec<Role>>,
}

impl Config {
    const ROLES: &'static [Role] = &[Role::SecurityAdministrator, Role::SystemAdministrator];

    fn base(&self) -> String {
        format!("/{}", self.base)
    }

    fn roles(&self) -> Vec<Role> {
        self.roles
            .as_ref()
            .map_or(Self::ROLES.to_owned(), Clone::clone)
    }

    fn uri(&self) -> &str {
        &self.uri
    }

    pub(crate) fn configure_reverse_proxies(
        store: &Arc<Store>,
        client: &Option<reqwest::Client>,
        reverse_proxies: &[Self],
    ) -> Vec<(ArchiveState, Router<ArchiveState>)> {
        reverse_proxies
            .iter()
            .map(|rp| {
                (
                    crate::archive::ArchiveState {
                        store: store.clone(),
                        client: client.clone(),
                        config: rp.clone(),
                    },
                    crate::archive::reverse_proxy(store.clone(), client.clone(), rp.clone()),
                )
            })
            .collect()
    }
}

#[derive(Clone, FromRef)]
pub(crate) struct ArchiveState {
    pub store: Arc<Store>,
    pub client: Option<reqwest::Client>,
    pub config: Config,
}

impl ArchiveState {
    pub(crate) fn base(&self) -> String {
        self.config.base()
    }
}

async fn auth(
    State(state): State<ArchiveState>,
    bearer: std::result::Result<TypedHeader<Authorization<Bearer>>, TypedHeaderRejection>,
    req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, Error> {
    let store = state.store;
    let client = state.client;
    let config = state.config;
    match (client, config) {
        (Some(_client), config) => {
            let bearer = bearer?;
            let roles = config.roles();
            let (_, role) = validate_token(&store, bearer.token())?;

            if roles.contains(&role) {
                Ok(next.run(req).await)
            } else {
                Err(Error::Unauthorized("Access denied".to_string()))
            }
        }
        _ => Err(Error::ServiceUnavailable(
            "proxy not configured".to_string(),
        )),
    }
}

async fn process_request(
    State(state): State<ArchiveState>,
    tail: Option<Path<String>>,
    req: Request<Body>,
) -> Result<Response, Error> {
    let (_store, client, config) = (state.store, state.client.unwrap(), state.config);

    let url = match tail {
        Some(Path(tail)) => format!("{}/{tail}", config.uri()),
        None => config.uri().into(),
    };

    let (parts, body) = req.into_parts();

    let method = parts.method;

    let builder = client.request(method, url);
    let request = builder
        .headers(parts.headers)
        .version(parts.version)
        .body(body)
        .build()?;

    let response = client.execute(request).await?;

    let mut builder = http::response::Builder::new()
        .status(response.status())
        .version(response.version());
    if let Some(hdr) = builder.headers_mut() {
        *hdr = response.headers().clone();
    }
    let bytes = response.bytes().await?;

    let body = boxed(Body::from(bytes));

    Ok(builder.body(body)?)
}

fn reverse_proxy(
    store: Arc<Store>,
    client: Option<reqwest::Client>,
    config: Config,
) -> Router<ArchiveState> {
    let state = ArchiveState {
        store,
        client,
        config,
    };

    Router::new()
        .route("/", post(process_request))
        .route("/*tail", post(process_request))
        .route_layer(from_fn_with_state(state, auth))
}

#[async_trait]
impl<S> FromRequestParts<S> for ArchiveState
where
    S: Send + Sync,
    ArchiveState: FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(ArchiveState::from_ref(state))
    }
}
