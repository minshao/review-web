use super::{Role, RoleGuard};
use async_graphql::{Context, Object, Result};
use review_database::Store;
use std::sync::Arc;

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup(&self, ctx: &Context<'_>, num_of_backups_to_keep: u32) -> Result<bool> {
        Ok(ctx
            .data::<Arc<Store>>()?
            .backup(num_of_backups_to_keep)
            .is_ok())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_latest_backup(&self, ctx: &Context<'_>) -> Result<bool> {
        Ok(ctx
            .data::<Arc<Store>>()?
            .restore_from_latest_backup()
            .is_ok())
    }
}
