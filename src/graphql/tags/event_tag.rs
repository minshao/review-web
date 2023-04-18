use super::{Role, Tag};
use crate::graphql::{triage::response, RoleGuard};
use async_graphql::{Context, Object, Result, ID};
use review_database::Store;
use std::sync::Arc;

#[derive(Default)]
pub(in crate::graphql) struct EventTagQuery;

#[Object]
impl EventTagQuery {
    /// A list of event tags.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_tag_list(&self, ctx: &Context<'_>) -> Result<Vec<Tag>> {
        let set = ctx.data::<Arc<Store>>()?.event_tag_set();
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
pub(in crate::graphql) struct EventTagMutation;

#[Object]
impl EventTagMutation {
    /// Inserts a new event tag, returning the ID of the new tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_event_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let set = ctx.data::<Arc<Store>>()?.event_tag_set();
        let id = set.insert(name.as_bytes())?;
        Ok(ID(id.to_string()))
    }

    /// Removes an event tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_event_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let id = id.0.parse::<u32>()?;

        let db = ctx.data::<Arc<Store>>()?;
        let tags = db.event_tag_set();
        let name = tags
            .deactivate(id)
            .map_err(|e| format!("failed to deactivate ID: {e:#}"))?;
        response::remove_tag(ctx, id)
            .map_err(|e| format!("failed to remove tag from networks: {}", e.message))?;
        tags.clear_inactive()
            .map_err(|e| format!("failed to clear inactive IDs: {e:#}"))?;

        Ok(Some(String::from_utf8_lossy(&name).into_owned()))
    }

    /// Updates the name of an event tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_event_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let set = ctx.data::<Arc<Store>>()?.event_tag_set();
        Ok(set.update(id.0.parse()?, old.as_bytes(), new.as_bytes())?)
    }
}
