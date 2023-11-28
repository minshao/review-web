use super::{slicing, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, ConnectionNameType, Edge, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use chrono::NaiveDateTime;
use review_database::{BatchInfo, Database};
use serde_json::Value as JsonValue;

#[derive(Default)]
pub(super) struct StatisticsQuery;

#[Object]
impl StatisticsQuery {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn column_statistics(
        &self,
        ctx: &Context<'_>,
        cluster: ID,
        time: Vec<NaiveDateTime>,
    ) -> Result<JsonValue> {
        let cluster = cluster.as_str().parse()?;
        let db = ctx.data::<Database>()?;
        let result = db.get_column_statistics(cluster, time).await?;
        Ok(serde_json::to_value(result)?)
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn rounds_by_cluster(
        &self,
        ctx: &Context<'_>,
        cluster: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Round, TotalCountByCluster, EmptyFields, RoundsByCluster>> {
        let cluster = cluster.as_str().parse()?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_rounds_by_cluster(ctx, cluster, &after, &before, first, last).await
            },
        )
        .await
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn rounds_by_model(
        &self,
        ctx: &Context<'_>,
        model: ID,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Round, TotalCountByModel, EmptyFields>> {
        let model = model.as_str().parse()?;
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_rounds_by_model(ctx, model, &after, &before, first, last).await
            },
        )
        .await
    }
}

struct TotalCountByCluster {
    cluster: i32,
}

#[Object]
impl TotalCountByCluster {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx.data::<Database>()?;
        Ok(db.count_rounds_by_cluster(self.cluster).await?)
    }
}

struct TotalCountByModel {
    model: i32,
}

#[Object]
impl TotalCountByModel {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        use num_traits::ToPrimitive;
        let store = super::get_store(ctx).await?;
        let map = store.batch_info_map();
        Ok(map
            .count(self.model)
            .map(|c| c.to_i64().unwrap_or_default())?)
    }
}

struct Round {
    inner: BatchInfo,
}

#[Object]
impl Round {
    async fn time(&self) -> NaiveDateTime {
        i64_to_naive_date_time(self.inner.inner.id)
    }

    async fn first_event_id(&self) -> i64 {
        self.inner.inner.earliest
    }

    async fn last_event_id(&self) -> i64 {
        self.inner.inner.latest
    }
}

impl From<BatchInfo> for Round {
    fn from(inner: BatchInfo) -> Self {
        Self { inner }
    }
}

async fn load_rounds_by_cluster(
    ctx: &Context<'_>,
    cluster: i32,
    after: &Option<String>,
    before: &Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Round, TotalCountByCluster, EmptyFields, RoundsByCluster>> {
    let after = slicing::decode_cursor(after)?.map(|(_, t)| t);
    let before = slicing::decode_cursor(before)?.map(|(_, t)| t);
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Database>()?;
    let (model, batches) = db
        .load_rounds_by_cluster(cluster, &after, &before, is_first, limit)
        .await?;

    let (batches, has_previous, has_next) = slicing::page_info(is_first, limit, batches);
    let batch_infos: Vec<_> = {
        let store = super::get_store(ctx).await?;
        let map = store.batch_info_map();
        let iter = batches
            .into_iter()
            .take(limit)
            .filter_map(|t| t.timestamp_nanos_opt())
            .filter_map(|t| {
                if let Ok(Some(b)) = map.get(model, t) {
                    Some(b)
                } else {
                    None
                }
            });
        if is_first {
            iter.collect()
        } else {
            iter.rev().collect()
        }
    };

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, TotalCountByCluster { cluster });
    connection.edges.extend(batch_infos.into_iter().map(|row| {
        let cursor = slicing::encode_cursor(cluster, i64_to_naive_date_time(row.inner.id));
        Edge::new(cursor, row.into())
    }));
    Ok(connection)
}

async fn load_rounds_by_model(
    ctx: &Context<'_>,
    model: i32,
    after: &Option<String>,
    before: &Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Round, TotalCountByModel, EmptyFields>> {
    let after: Option<i64> = slicing::decode_cursor(after)?.map(|(_, t)| t);
    let before: Option<i64> = slicing::decode_cursor(before)?.map(|(_, t)| t);
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let store = super::get_store(ctx).await?;
    let map = store.batch_info_map();
    let batch_infos: Vec<BatchInfo> = map.get_before_after(model, before, after)?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, batch_infos);
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, TotalCountByModel { model });
    connection.edges.extend(rows.into_iter().map(|row| {
        let cursor = slicing::encode_cursor(row.model, row.inner.id);
        Edge::new(cursor, row.into())
    }));
    Ok(connection)
}

fn i64_to_naive_date_time(t: i64) -> NaiveDateTime {
    use num_traits::ToPrimitive;
    const A_BILLION: i64 = 1_000_000_000;
    NaiveDateTime::from_timestamp_opt(t / A_BILLION, (t % A_BILLION).to_u32().unwrap_or_default())
        .unwrap_or_default()
}

struct RoundsByCluster;

impl ConnectionNameType for RoundsByCluster {
    fn type_name<T: crate::graphql::OutputType>() -> String {
        "RoundsByClusterConnection".to_string()
    }
}
