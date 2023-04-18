use super::{BoxedAgentManager, Role, RoleGuard};
use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database::{self as database, Store};
use std::sync::Arc;

#[derive(Default)]
pub(super) struct TrafficFilterQuery;

#[Object]
impl TrafficFilterQuery {
    /// traffic filtering rules of agents.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn traffic_filter_list(
        &self,
        ctx: &Context<'_>,
        agents: Option<Vec<String>>,
    ) -> Result<Option<Vec<TrafficFilter>>> {
        let store = ctx.data::<Arc<Store>>()?;
        let res = database::TrafficFilter::get_list(store, &agents)?;
        Ok(res.map(|r| r.into_iter().map(Into::into).collect()))
    }
}

#[derive(Default)]
pub(super) struct TrafficFilterMutation;

#[Object]
impl TrafficFilterMutation {
    /// inserts traffic filtering rules
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn insert_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agent: String,
        rules: Vec<String>,
    ) -> Result<usize> {
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::insert(store, &agent, &rules).map_err(Into::into)
    }

    /// clears traffic filtering rules
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn clear_traffic_filter_rules(&self, ctx: &Context<'_>, agent: String) -> Result<usize> {
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::clear(store, &agent).map_err(Into::into)
    }

    /// replaces traffic filtering rules of multiple agents
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn replace_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agents: Vec<String>,
        rules: Vec<String>,
    ) -> Result<usize> {
        let store = ctx.data::<Arc<Store>>()?;
        let mut success = 0;
        for agent in &agents {
            let tf = database::TrafficFilter::new(agent, &rules)?;
            tf.replace(store)?;
            success += 1;
        }
        Ok(success)
    }

    /// removes traffic filtering rules from the agent
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn remove_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agent: String,
        rules: Vec<String>,
    ) -> Result<usize> {
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::remove(store, &agent, &rules).map_err(Into::into)
    }

    /// applies traffic filtering rules to the agents if it is connected
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn apply_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agents: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = ctx.data::<Arc<Store>>()?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        let mut res = Vec::new();
        for agent in &agents {
            if let Some(tf) = database::TrafficFilter::get(store, agent)? {
                if let Err(e) = agent_manager
                    .update_traffic_filter_rules(agent, tf.rules())
                    .await
                {
                    res.push(format!("{agent}: update request failed. {e:?}"));
                } else {
                    database::TrafficFilter::update_time(store, agent)?;
                    res.push(format!("{agent}: {} rules are updated.", tf.len()));
                }
            }
        }
        Ok(res)
    }
}

struct TrafficFilter {
    inner: database::TrafficFilter,
}

#[Object]
impl TrafficFilter {
    /// Agent name
    async fn agent(&self) -> &str {
        &self.inner.agent
    }

    /// The traffic filter rules.
    async fn rules(&self) -> Vec<String> {
        self.inner.rules.iter().map(ToString::to_string).collect()
    }

    /// The last modification time.
    async fn last_modification_time(&self) -> DateTime<Utc> {
        self.inner.last_modification_time
    }

    /// The time when rules are applied to the agent successfully.
    async fn update_time(&self) -> String {
        if let Some(t) = self.inner.update_time {
            t.format("%Y-%m-%d %H:%M:%S").to_string()
        } else {
            "-".to_string()
        }
    }
}

impl From<database::TrafficFilter> for TrafficFilter {
    fn from(inner: database::TrafficFilter) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn traffic_filter_list() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c1@sun"
                        rules: ["192.168.0.0/24", "164.124.101.2/32"]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 2}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c2@moon"
                        rules: ["192.168.0.0/24"]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 1}"#);

        let res = schema
            .execute(
                r#"query {
                    trafficFilterList(agents: null) {
                        agent
                        rules
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{trafficFilterList: [{agent: "c1@sun",rules: ["192.168.0.0/24","164.124.101.2/32"]},{agent: "c2@moon",rules: ["192.168.0.0/24"]}]}"#
        );
    }
}
