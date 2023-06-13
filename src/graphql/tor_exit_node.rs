use super::{Role, RoleGuard};
use anyhow::Context as _;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use review_database::{types::FromKeyValue, IterableMap};

#[derive(Default)]
pub(super) struct TorExitNodeQuery;

#[Object]
impl TorExitNodeQuery {
    /// A list of tor exit nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn tor_exit_node_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TorExitNode, TorExitNodeTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct TorExitNodeMutation;

#[Object]
impl TorExitNodeMutation {
    /// Delete all existing entries and add new IP address(es)
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_tor_exit_node_list(
        &self,
        ctx: &Context<'_>,
        ip_addresses: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.tor_exit_node_map();
        let timestamp = Utc::now().to_string();
        let entries = ip_addresses
            .iter()
            .map(|addr| (addr.as_bytes(), timestamp.as_bytes()))
            .collect::<Vec<_>>();
        map.replace_all(&entries)?;
        Ok(ip_addresses)
    }
}

#[derive(SimpleObject)]
struct TorExitNode {
    ip_address: String,
    updated_at: DateTime<Utc>,
}

impl FromKeyValue for TorExitNode {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        let ip_address =
            String::from_utf8(key.to_vec()).context("invalid IP address in database")?;
        let updated_at = String::from_utf8(value.to_vec())
            .context("invalid timestamp in database")?
            .parse()
            .context("invalid timestamp in database")?;
        Ok(TorExitNode {
            ip_address,
            updated_at,
        })
    }
}

struct TorExitNodeTotalCount;

#[Object]
impl TorExitNodeTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.tor_exit_node_map();
        let count = map.iter_forward()?.count();
        Ok(count)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TorExitNode, TorExitNodeTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.tor_exit_node_map();
    super::load(&map, after, before, first, last, TorExitNodeTotalCount)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_query_and_mutation() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r#"query{torExitNodeList(first:10){edges{node{ipAddress}}}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{torExitNodeList: {edges: []}}"#);

        let res = schema
            .execute(r#"mutation{updateTorExitNodeList(ipAddresses:["192.168.1.1"])}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{updateTorExitNodeList: ["192.168.1.1"]}"#
        );

        let res = schema
            .execute(r#"query{torExitNodeList(first:10){edges{node{ipAddress}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{torExitNodeList: {edges: [{node: {ipAddress: "192.168.1.1"}}]}}"#
        );

        let res = schema
            .execute(r#"mutation{updateTorExitNodeList(ipAddresses:["192.168.1.2"])}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{updateTorExitNodeList: ["192.168.1.2"]}"#
        );

        let res = schema
            .execute(r#"query{torExitNodeList(first:10){edges{node{ipAddress}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{torExitNodeList: {edges: [{node: {ipAddress: "192.168.1.2"}}]}}"#
        );
    }
}
