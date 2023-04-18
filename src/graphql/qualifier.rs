use super::{slicing, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use review_database::{self as database, Database};

#[derive(Default)]
pub(super) struct QualifierQuery;

#[Object]
impl QualifierQuery {
    /// A list of qualifiers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn qualifiers(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Qualifier, QualifierTotalCount, EmptyFields>> {
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
pub(super) struct QualifierMutation;

#[Object]
impl QualifierMutation {
    /// Adds a new qualifier.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn add_qualifier(&self, ctx: &Context<'_>, description: String) -> Result<ID> {
        let db = ctx.data::<Database>()?;
        Ok(ID(db.add_qualifier(&description).await?.to_string()))
    }

    /// Updates the given qualifier's description.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_qualifier(&self, ctx: &Context<'_>, id: ID, description: String) -> Result<ID> {
        let db = ctx.data::<Database>()?;
        db.update_qualifier(id.as_str().parse()?, &description)
            .await?;
        Ok(id)
    }
}

pub(super) struct Qualifier {
    inner: database::Qualifier,
}

#[Object]
impl Qualifier {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }
}

impl From<database::Qualifier> for Qualifier {
    fn from(inner: database::Qualifier) -> Self {
        Self { inner }
    }
}

struct QualifierTotalCount;

#[Object]
impl QualifierTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<i64> {
        let db = ctx.data::<Database>()?;
        Ok(db.count_qualifiers().await?)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Qualifier, QualifierTotalCount, EmptyFields>> {
    let after = slicing::decode_cursor(&after)?;
    let before = slicing::decode_cursor(&before)?;
    let is_first = first.is_some();
    let limit = slicing::limit(first, last)?;
    let db = ctx.data::<Database>()?;
    let rows = db.load_qualifiers(&after, &before, is_first, limit).await?;

    let (rows, has_previous, has_next) = slicing::page_info(is_first, limit, rows);
    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, QualifierTotalCount);
    connection.edges.extend(rows.into_iter().map(|row| {
        let cursor = slicing::encode_cursor(row.id, &row.description);
        Edge::new(cursor, row.into())
    }));
    Ok(connection)
}
