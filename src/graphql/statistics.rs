use super::{slicing, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use chrono::NaiveDateTime;
use data_encoding::BASE64;
use review_database::{self as database, Database};
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
    ) -> Result<Connection<String, RoundByCluster, TotalCountByCluster, EmptyFields>> {
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
    ) -> Result<Connection<String, RoundByModel, TotalCountByModel, EmptyFields>> {
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

struct RoundByCluster {
    inner: database::RoundByCluster,
}

#[Object]
impl RoundByCluster {
    async fn time(&self) -> NaiveDateTime {
        self.inner.time
    }

    async fn first_event_id(&self) -> i64 {
        self.inner.first_event_id
    }

    async fn last_event_id(&self) -> i64 {
        self.inner.last_event_id
    }
}

impl From<database::RoundByCluster> for RoundByCluster {
    fn from(inner: database::RoundByCluster) -> Self {
        Self { inner }
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
        let db = ctx.data::<Database>()?;
        Ok(db.count_rounds_by_model(self.model).await?)
    }
}

struct RoundByModel {
    inner: database::RoundByModel,
}

#[Object]
impl RoundByModel {
    async fn time(&self) -> NaiveDateTime {
        self.inner.time
    }
}

impl From<database::RoundByModel> for RoundByModel {
    fn from(inner: database::RoundByModel) -> Self {
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
) -> Result<Connection<String, RoundByCluster, TotalCountByCluster, EmptyFields>> {
    let after = slicing::decode_cursor(after)?;
    let before = slicing::decode_cursor(before)?;
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Database>()?;
    let rows = db
        .load_rounds_by_cluster(cluster, &after, &before, is_first, limit)
        .await?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, TotalCountByCluster { cluster });
    connection.edges.extend(rows.into_iter().map(|row| {
        let cursor = BASE64.encode(format!("{}:{:?}", row.id, row.time).as_bytes());
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
) -> Result<Connection<String, RoundByModel, TotalCountByModel, EmptyFields>> {
    let after = slicing::decode_cursor(after)?;
    let before = slicing::decode_cursor(before)?;
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Database>()?;
    let rows = db
        .load_rounds_by_model(model, &after, &before, is_first, limit)
        .await?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, TotalCountByModel { model });
    connection.edges.extend(rows.into_iter().map(|row| {
        let cursor = BASE64.encode(format!("{}:{:?}", row.id, row.time).as_bytes());
        Edge::new(cursor, row.into())
    }));
    Ok(connection)
}
