use super::{Role, Tag};
use crate::graphql::{network, RoleGuard};
use async_graphql::{Context, Object, Result, ID};

#[derive(Default)]
pub(in crate::graphql) struct NetworkTagQuery;

#[Object]
impl NetworkTagQuery {
    /// A list of network tags.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn network_tag_list(&self, ctx: &Context<'_>) -> Result<Vec<Tag>> {
        let store = crate::graphql::get_store(ctx).await?;
        let set = store.network_tag_set();
        let index = set.index()?;
        Ok(index
            .iter()
            .map(|(id, name)| Tag {
                id,
                name: String::from_utf8_lossy(name).into_owned(),
            })
            .collect())
    }
}

#[derive(Default)]
pub(in crate::graphql) struct NetworkTagMutation;

#[Object]
impl NetworkTagMutation {
    /// Inserts a new network tag, returning the ID of the new tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_network_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx).await?;
        let set = store.network_tag_set();
        let id = set.insert(name.as_bytes())?;
        Ok(ID(id.to_string()))
    }

    /// Removes a network tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_network_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let id = id.0.parse::<u32>()?;

        let name = {
            let store = crate::graphql::get_store(ctx).await?;
            let tags = store.network_tag_set();
            tags.deactivate(id)
                .map_err(|e| format!("failed to deactivate ID: {e:#}"))?
        };
        network::remove_tag(ctx, id)
            .await
            .map_err(|e| format!("failed to remove tag from networks: {}", e.message))?;
        {
            let store = crate::graphql::get_store(ctx).await?;
            let tags = store.network_tag_set();
            tags.clear_inactive()
                .map_err(|e| format!("failed to clear inactive IDs: {e:#}"))?;
        }

        Ok(Some(String::from_utf8_lossy(&name).into_owned()))
    }

    /// Updates the name of a network tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_network_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let set = store.network_tag_set();
        Ok(set.update(id.0.parse()?, old.as_bytes(), new.as_bytes())?)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn network_tag() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{networkTagList{name}}"#).await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: []}"#);

        let res = schema
            .execute(r#"mutation {insertNetworkTag(name: "foo")}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetworkTag: "0"}"#);

        let res = schema.execute(r#"{networkTagList{name}}"#).await;
        assert_eq!(res.data.to_string(), r#"{networkTagList: [{name: "foo"}]}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNetwork(name: "n1", description: "", networks: {
                        hosts: [], networks: [], ranges: []
                    }, customerIds: [], tagIds: [0])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNetwork: "0"}"#);

        let res = schema.execute(r#"{network(id: "0") {tagIds}}"#).await;
        assert_eq!(res.data.to_string(), r#"{network: {tagIds: [0]}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    removeNetworkTag(id: "0")
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNetworkTag: "foo"}"#);

        let res = schema.execute(r#"{network(id: "0") {tagIds}}"#).await;
        assert_eq!(res.data.to_string(), r#"{network: {tagIds: []}}"#);
    }
}
