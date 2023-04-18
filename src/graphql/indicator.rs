use crate::graphql::{Role, RoleGuard};
use async_graphql::{Context, Object, Result, SimpleObject};
use chrono::{DateTime, Utc};
use review_database::{self as database, Store};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct IndicatorQuery;

#[Object]
impl IndicatorQuery {
    /// Look up an Indicator by the given name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn indicator(&self, ctx: &Context<'_>, name: String) -> Result<Option<ModelIndicator>> {
        let store = ctx.data::<Arc<Store>>()?;
        database::ModelIndicator::get(store, &name)
            .map(|indicator| indicator.map(Into::into))
            .map_err(Into::into)
    }

    /// A list of Indicators.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn indicator_list(&self, ctx: &Context<'_>) -> Result<Vec<ModelIndicatorOutput>> {
        let store = ctx.data::<Arc<Store>>()?;
        database::ModelIndicator::get_list(store)
            .map(|list| {
                list.into_iter()
                    .map(|(name, indicator)| ModelIndicatorOutput {
                        name,
                        indicator: indicator.into(),
                    })
                    .collect()
            })
            .map_err(Into::into)
    }
}

#[derive(Default)]
pub(super) struct IndicatorMutation;

#[Object]
impl IndicatorMutation {
    /// Inserts a new Indicator, overwriting any existing Indicator if same name and version exist already.
    /// Returns the inserted db's name and version.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_indicator(
        &self,
        ctx: &Context<'_>,
        name: String,
        dbfile: String,
    ) -> Result<String> {
        let indicator = database::ModelIndicator::new(&dbfile)?;
        let store = ctx.data::<Arc<Store>>()?;
        indicator.insert(store, &name).map_err(Into::into)
    }

    /// Removes Indicator, returning the db's name and version that no longer exist.
    ///
    /// On error, some Indicators may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_indicator(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] names: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = ctx.data::<Arc<Store>>()?;
        database::ModelIndicator::remove(store, &names).map_err(Into::into)
    }

    /// Updates the given indicator, returning the indicator name that was updated.
    ///
    /// Will return error if it failed to access database
    /// Will return error if it failed to delete or add indicator into database
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_indicator(
        &self,
        ctx: &Context<'_>,
        name: String,
        new: String,
    ) -> Result<String> {
        let indicator = database::ModelIndicator::new(&new)?;
        let store = ctx.data::<Arc<Store>>()?;
        indicator.update(store, &name).map_err(Into::into)
    }
}

struct ModelIndicator {
    inner: database::ModelIndicator,
}

#[Object]
impl ModelIndicator {
    /// The description of the model indicator.
    async fn description(&self) -> &str {
        &self.inner.description
    }

    /// The model ID of the model indicator.
    async fn model_id(&self) -> i32 {
        self.inner.model_id
    }

    /// The size of the model indicator.
    async fn size(&self) -> usize {
        self.inner.tokens.len()
    }

    /// The last modified time of the model indicator.
    async fn last_modified(&self) -> DateTime<Utc> {
        self.inner.last_modification_time
    }
}

impl From<database::ModelIndicator> for ModelIndicator {
    fn from(inner: database::ModelIndicator) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
#[allow(clippy::module_name_repetitions)]
pub struct ModelIndicatorOutput {
    name: String,
    indicator: ModelIndicator,
}
