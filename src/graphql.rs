//! The GraphQL API schema and implementation.

// async-graphql requires the API functions to be `async`.
#![allow(clippy::unused_async)]

pub mod account;
mod allow_network;
mod block_network;
mod category;
mod cert;
mod cluster;
pub(crate) mod customer;
mod data_source;
mod db_management;
mod event;
mod filter;
pub(crate) mod indicator;
mod ip_location;
mod model;
pub(crate) mod network;
mod node;
mod outlier;
mod qualifier;
mod sampling;
mod slicing;
mod statistics;
mod status;
mod tags;
mod template;
pub(crate) mod tidb;
mod tor_exit_node;
mod traffic_filter;
mod triage;
mod trusted_domain;

pub use self::cert::ParsedCertificate;
pub use self::node::get_node_settings;
use async_graphql::{
    connection::{Connection, Edge, EmptyFields},
    Context, EmptySubscription, Guard, MergedObject, ObjectType, OutputType, Result,
};
use async_trait::async_trait;
use chrono::Duration;
use data_encoding::BASE64;
use ipnet::IpNet;
use num_traits::ToPrimitive;
use review_database::{
    self as database, types::FromKeyValue, Database, Direction, IterableMap, Role, Store,
};
use std::{
    cmp,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;
use vinum::signal;

/// GraphQL schema type.
pub(super) type Schema = async_graphql::Schema<Query, Mutation, EmptySubscription>;

#[async_trait]
pub trait AgentManager: Send + Sync {
    async fn broadcast_to_crusher(&self, message: &[u8]) -> Result<(), anyhow::Error>;
    async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error>;
    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error>;
    async fn send_and_recv(&self, key: &str, msg: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    async fn update_traffic_filter_rules(
        &self,
        key: &str,
        rules: &[IpNet],
    ) -> Result<(), anyhow::Error>;
}

type BoxedAgentManager = Box<dyn AgentManager>;

pub trait CertManager: Send + Sync {
    fn cert_path(&self) -> Result<PathBuf, anyhow::Error>;
    fn key_path(&self) -> Result<PathBuf, anyhow::Error>;
    fn update_certificate(
        &self,
        cert: String,
        key: String,
    ) -> Result<Vec<ParsedCertificate>, anyhow::Error>;
}

/// Builds a GraphQL schema with the given database connection pool as its
/// context.
///
/// The connection pool is stored in `async_graphql::Context` and passed to
/// every GraphQL API function.
pub(super) fn schema<B>(
    db: Database,
    store: Arc<Store>,
    agent_manager: B,
    ip_locator: Option<Arc<Mutex<ip2location::DB>>>,
    cert_manager: Arc<dyn CertManager>,
    cert_reload_handle: Arc<Notify>,
) -> Schema
where
    B: AgentManager + 'static,
{
    let agent_manager: BoxedAgentManager = Box::new(agent_manager);
    let mut builder = Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .data(db)
        .data(store)
        .data(agent_manager)
        .data(cert_manager)
        .data(cert_reload_handle);
    if let Some(ip_locator) = ip_locator {
        builder = builder.data(ip_locator);
    }
    builder.finish()
}

/// A set of queries defined in the schema.
#[derive(MergedObject, Default)]
pub(super) struct Query(
    account::AccountQuery,
    block_network::BlockNetworkQuery,
    category::CategoryQuery,
    cluster::ClusterQuery,
    customer::CustomerQuery,
    data_source::DataSourceQuery,
    event::EventQuery,
    event::EventGroupQuery,
    filter::FilterQuery,
    indicator::IndicatorQuery,
    ip_location::IpLocationQuery,
    model::ModelQuery,
    network::NetworkQuery,
    node::NodeQuery,
    node::NodeStatusQuery,
    qualifier::QualifierQuery,
    outlier::OutlierQuery,
    sampling::SamplingPolicyQuery,
    statistics::StatisticsQuery,
    status::StatusQuery,
    tags::EventTagQuery,
    tags::NetworkTagQuery,
    template::TemplateQuery,
    tor_exit_node::TorExitNodeQuery,
    tidb::TidbQuery,
    triage::TriagePolicyQuery,
    triage::TriageResponseQuery,
    trusted_domain::TrustedDomainQuery,
    traffic_filter::TrafficFilterQuery,
    allow_network::AllowNetworkQuery,
);

/// A set of mutations defined in the schema.
///
/// This is exposed only for [`Schema`], and not used directly.
#[derive(MergedObject, Default)]
pub(super) struct Mutation(
    account::AccountMutation,
    block_network::BlockNetworkMutation,
    category::CategoryMutation,
    cert::CertMutation,
    cluster::ClusterMutation,
    customer::CustomerMutation,
    data_source::DataSourceMutation,
    db_management::DbManagementMutation,
    filter::FilterMutation,
    indicator::IndicatorMutation,
    model::ModelMutation,
    network::NetworkMutation,
    node::NodeControlMutation,
    node::NodeMutation,
    outlier::OutlierMutation,
    qualifier::QualifierMutation,
    sampling::SamplingPolicyMutation,
    status::StatusMutation,
    tags::EventTagMutation,
    tags::NetworkTagMutation,
    template::TemplateMutation,
    tor_exit_node::TorExitNodeMutation,
    tidb::TidbMutation,
    triage::TriagePolicyMutation,
    triage::TriageResponseMutation,
    trusted_domain::TrustedDomainMutation,
    traffic_filter::TrafficFilterMutation,
    allow_network::AllowNetworkMutation,
);

#[derive(Debug)]
pub struct ParseEnumError;

const DEFAULT_CONNECTION_SIZE: usize = 100;

// parameters for trend
const DEFAULT_CUTOFF_RATE: f64 = 0.1;
const DEFAULT_TRENDI_ORDER: i32 = 4;

#[allow(clippy::type_complexity)] // since this is called within `load` only
fn load_nodes<'m, M, I, N, NI>(
    map: &'m M,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(Vec<(String, N)>, bool, bool)>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
    N: From<NI> + OutputType,
    NI: FromKeyValue,
{
    load_nodes_with_filter(map, |n| Some(n), after, before, first, last)
}

#[allow(clippy::type_complexity)] // since this is called within `load` only
fn load_nodes_with_filter<'m, M, I, N, NI>(
    map: &'m M,
    filter: fn(N) -> Option<N>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(Vec<(String, N)>, bool, bool)>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
    N: From<NI> + OutputType,
    NI: FromKeyValue,
{
    if let Some(last) = last {
        let iter = if let Some(before) = before {
            let end = latest_key(&before)?;
            map.iter_from(&end, Direction::Reverse)?
        } else {
            map.iter_backward()?
        };

        let (nodes, has_more) = if let Some(after) = after {
            let to = earliest_key(&after)?;
            iter_to_nodes_with_filter(iter, &to, cmp::Ordering::is_ge, filter, last)
        } else {
            iter_to_nodes_with_filter(iter, &[], always_true, filter, last)
        }?;
        Ok((nodes, has_more, false))
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = if let Some(after) = after {
            let start = earliest_key(&after)?;
            map.iter_from(&start, Direction::Forward)?
        } else {
            map.iter_forward()?
        };

        let (nodes, has_more) = if let Some(before) = before {
            let to = latest_key(&before)?;
            iter_to_nodes_with_filter(iter, &to, cmp::Ordering::is_le, filter, first)
        } else {
            iter_to_nodes_with_filter(iter, &[], always_true, filter, first)
        }?;
        Ok((nodes, false, has_more))
    }
}

fn load_with_filter<'m, M, I, N, NI, T>(
    map: &'m M,
    filter: fn(N) -> Option<N>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    total_count: T,
) -> Result<Connection<String, N, T, EmptyFields>>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
    N: From<NI> + OutputType,
    NI: FromKeyValue,
    T: ObjectType,
{
    let (nodes, has_previous, has_next) =
        load_nodes_with_filter(map, filter, after, before, first, last)?;

    let mut connection = Connection::with_additional_fields(has_previous, has_next, total_count);
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev)));
    Ok(connection)
}

fn load<'m, M, I, N, NI, T>(
    map: &'m M,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    total_count: T,
) -> Result<Connection<String, N, T, EmptyFields>>
where
    M: IterableMap<'m, I>,
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'm,
    N: From<NI> + OutputType,
    NI: FromKeyValue,
    T: ObjectType,
{
    let (nodes, has_previous, has_next) =
        load_nodes_with_filter(map, |x| Some(x), after, before, first, last)?;

    let mut connection = Connection::with_additional_fields(has_previous, has_next, total_count);
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev)));
    Ok(connection)
}

fn iter_to_nodes_with_filter<I, N, NI>(
    iter: I,
    to: &[u8],
    cond: fn(cmp::Ordering) -> bool,
    filter: fn(N) -> Option<N>,
    len: usize,
) -> Result<(Vec<(String, N)>, bool)>
where
    I: Iterator<Item = (Box<[u8]>, Box<[u8]>)>,
    N: From<NI>,
    NI: FromKeyValue,
{
    let mut nodes = Vec::new();
    let mut exceeded = false;
    for (k, v) in iter {
        if !(cond)(k.as_ref().cmp(to)) {
            break;
        }

        let cursor = BASE64.encode(&k);
        let Some(node) = filter(NI::from_key_value(&k, &v)?.into()) else {continue;};

        nodes.push((cursor, node));
        exceeded = nodes.len() > len;
        if exceeded {
            break;
        }
    }
    if exceeded {
        nodes.pop();
    }
    Ok((nodes, exceeded))
}

fn earliest_key(after: &str) -> Result<Vec<u8>> {
    let mut start = BASE64
        .decode(after.as_bytes())
        .map_err(|_| "invalid cursor `after`")?;
    start.push(0);
    Ok(start)
}

fn latest_key(before: &str) -> Result<Vec<u8>> {
    let mut end = BASE64
        .decode(before.as_bytes())
        .map_err(|_| "invalid cursor `before`")?;
    let last_byte = if let Some(b) = end.last_mut() {
        *b
    } else {
        return Err("invalid cursor `before`".into());
    };
    end.pop();
    if last_byte > 0 {
        end.push(last_byte - 1);
    }
    Ok(end)
}

fn always_true(_ordering: cmp::Ordering) -> bool {
    true
}

struct RoleGuard {
    role: database::Role,
}

impl RoleGuard {
    fn new(role: database::Role) -> Self {
        Self { role }
    }
}

#[async_trait::async_trait]
impl Guard for RoleGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<()> {
        if ctx.data_opt::<Role>() == Some(&self.role) {
            Ok(())
        } else {
            Err("Forbidden".into())
        }
    }
}

fn fill_vacant_time_slots(series: &[database::TimeCount]) -> Vec<database::TimeCount> {
    let mut filled_series: Vec<database::TimeCount> = Vec::new();

    if series.len() <= 2 {
        return series.to_vec();
    }

    let mut min_diff = series[1].time - series[0].time;
    for index in 2..series.len() {
        let diff = series[index].time - series[index - 1].time;
        if diff < min_diff {
            min_diff = diff;
        }
    }

    for (index, element) in series.iter().enumerate() {
        if index == 0 {
            filled_series.push(element.clone());
            continue;
        }
        let time_diff =
            (element.time - series[index - 1].time).num_seconds() / min_diff.num_seconds();
        if time_diff > 1 {
            for d in 1..time_diff {
                filled_series.push(database::TimeCount {
                    time: series[index - 1].time + Duration::seconds(d * min_diff.num_seconds()),
                    count: 0,
                });
            }
        }
        filled_series.push(element.clone());
    }
    filled_series
}

fn get_trend(
    series: &[database::TimeCount],
    cutoff_rate: f64,
    trendi_order: i32,
) -> Result<Vec<f64>, vinum::InvalidInput> {
    let original: Vec<f64> = series
        .iter()
        .map(|s| s.count.to_f64().expect("safe: usize -> f64"))
        .collect();
    let cutoff_len = cutoff_rate * original.len().to_f64().expect("safe: usize -> f64");
    let cutoff_frequency = if cutoff_len < 1.0 {
        1.0
    } else {
        1.0 / cutoff_len
    };
    let (b, a) = signal::filter::design::butter(trendi_order, cutoff_frequency);
    signal::filter::filtfilt(&b, &a, &original)
}

#[cfg(test)]
struct MockAgentManager {}

#[cfg(test)]
#[async_trait]
impl AgentManager for MockAgentManager {
    async fn broadcast_to_crusher(&self, _msg: &[u8]) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
    async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(HashMap::new())
    }
    async fn send_and_recv(&self, _key: &str, _msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        unimplemented!()
    }
    async fn update_traffic_filter_rules(
        &self,
        _key: &str,
        _rules: &[IpNet],
    ) -> Result<(), anyhow::Error> {
        unimplemented!()
    }
}

#[cfg(test)]
struct TestSchema {
    _dir: tempfile::TempDir, // to delete the data directory when dropped
    store: Arc<Store>,
    schema: Schema,
}

#[cfg(test)]
impl TestSchema {
    async fn new() -> Self {
        use self::account::set_initial_admin_password;

        let db_dir = tempfile::tempdir().unwrap();
        let backup_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::new(db_dir.path(), backup_dir.path()).unwrap());
        let _ = set_initial_admin_password(&store);
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let schema = Schema::build(
            Query::default(),
            Mutation::default(),
            async_graphql::EmptySubscription,
        )
        .data(agent_manager)
        .data(store.clone())
        .data("testuser".to_string())
        .finish();
        Self {
            _dir: db_dir,
            store,
            schema,
        }
    }

    fn event_database(&self) -> database::EventDb {
        self.store.events()
    }

    async fn execute(&self, query: &str) -> async_graphql::Response {
        let request: async_graphql::Request = query.into();
        self.schema
            .execute(request.data(Role::SystemAdministrator))
            .await
    }
}
