use super::{AgentManager, BoxedAgentManager, FromKeyValue, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Object, Result, SimpleObject,
};

#[derive(Default)]
pub(super) struct TrustedDomainQuery;

#[Object]
impl TrustedDomainQuery {
    /// A list of trusted domains.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn trusted_domain_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TrustedDomain, EmptyFields, EmptyFields>> {
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
pub(super) struct TrustedDomainMutation;

#[Object]
impl TrustedDomainMutation {
    /// Inserts a new trusted domain, returning the last remarks if it was set.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_trusted_domain(
        &self,
        ctx: &Context<'_>,
        name: String,
        remarks: String,
    ) -> Result<String> {
        {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.trusted_dns_server_map();
            map.put(name.as_bytes(), remarks.as_bytes())?;
        }

        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager.broadcast_trusted_domains().await?;
        Ok(name)
    }

    /// Removes a trusted domain, returning the old value if it existed.
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn remove_trusted_domain(&self, ctx: &Context<'_>, name: String) -> Result<String> {
        {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.trusted_dns_server_map();
            map.delete(name.as_bytes())?;
        }

        let agent_manager = ctx.data::<Box<dyn AgentManager>>()?;
        agent_manager.broadcast_trusted_domains().await?;
        Ok(name)
    }
}

#[derive(SimpleObject)]
pub(super) struct TrustedDomain {
    name: String,
    remarks: String,
}

impl FromKeyValue for TrustedDomain {
    fn from_key_value(key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(TrustedDomain {
            name: String::from_utf8_lossy(key).into_owned(),
            remarks: String::from_utf8_lossy(value).into_owned(),
        })
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TrustedDomain, EmptyFields, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.trusted_dns_server_map();
    super::load(&map, after, before, first, last, EmptyFields)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn trusted_domain_list() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r#"{trustedDomainList{edges{node{name}}}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{trustedDomainList: {edges: []}}"#);
    }
}
