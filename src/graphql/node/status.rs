use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    Node, NodeStatus, NodeStatusQuery, NodeStatusTotalCount,
};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, Object, Result,
};
use bincode::Options;
use oinq::RequestCode;
use review_database::Store;
use roxy::ResourceUsage;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[Object]
impl NodeStatusQuery {
    /// A list of status of all the nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_status_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
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

#[allow(clippy::too_many_lines)]
async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
    let agents = ctx.data::<BoxedAgentManager>()?;
    let apps = agents.online_apps_by_host_id().await?;
    let hostname_key = apps
        .iter()
        .filter_map(|(h, a)| a.first().map(move |(k, _)| (h.clone(), k.clone())))
        .collect::<Vec<(String, String)>>();
    let code: u32 = RequestCode::ResourceUsage.into();
    let msg = bincode::serialize(&code)?;
    let mut usages: HashMap<String, ResourceUsage> = HashMap::new();
    for (_, key) in hostname_key {
        if let Ok(response) = agents.send_and_recv(&key, &msg).await {
            if let Ok(Ok((hostname, ru))) = bincode::DefaultOptions::new()
                .deserialize::<Result<(String, ResourceUsage), &str>>(&response)
            {
                usages.insert(
                    hostname,
                    ResourceUsage {
                        cpu_usage: ru.cpu_usage,
                        total_memory: ru.total_memory,
                        used_memory: ru.used_memory,
                        total_disk_space: ru.total_disk_space,
                        used_disk_space: ru.used_disk_space,
                    },
                );
            }
        }
    }

    let review_usage = roxy::resource_usage().await;
    let review_hostname = roxy::hostname();

    let db = ctx.data::<Arc<Store>>()?;
    let map = db.node_map();
    let (node_list, has_previous, has_next): (Vec<(String, Node)>, bool, bool) =
        super::super::load_nodes(&map, after, before, first, last)?;

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, NodeStatusTotalCount);
    connection
        .edges
        .extend(node_list.into_iter().map(move |(k, ev)| {
            let (
                review,
                piglet,
                giganto,
                reconverge,
                hog,
                cpu_usage,
                total_memory,
                used_memory,
                total_disk_space,
                used_disk_space,
            ) = if let (Some(modules), Some(usage)) =
                (apps.get(&ev.hostname), usages.get(&ev.hostname))
            {
                let module_names = modules
                    .iter()
                    .map(|(_, m)| m.clone())
                    .collect::<HashSet<String>>();
                let (review, piglet, giganto, reconverge, hog) = (
                    module_names.contains(&"review".to_string()),
                    module_names.contains(&"piglet".to_string()),
                    module_names.contains(&"giganto".to_string()),
                    module_names.contains(&"reconverge".to_string()),
                    module_names.contains(&"hog".to_string()),
                );
                (
                    Some(review),
                    Some(piglet),
                    Some(giganto),
                    Some(reconverge),
                    Some(hog),
                    Some(usage.cpu_usage),
                    Some(usage.total_memory),
                    Some(usage.used_memory),
                    Some(usage.total_disk_space),
                    Some(usage.used_disk_space),
                )
            } else if !review_hostname.is_empty() && review_hostname == ev.hostname {
                (
                    Some(true),
                    None,
                    None,
                    None,
                    None,
                    Some(review_usage.cpu_usage),
                    Some(review_usage.total_memory),
                    Some(review_usage.used_memory),
                    Some(review_usage.total_disk_space),
                    Some(review_usage.used_disk_space),
                )
            } else {
                (None, None, None, None, None, None, None, None, None, None)
            };
            Edge::new(
                k,
                NodeStatus::new(
                    ev.id,
                    ev.name,
                    cpu_usage,
                    total_memory,
                    used_memory,
                    total_disk_space,
                    used_disk_space,
                    review,
                    piglet,
                    giganto,
                    reconverge,
                    hog,
                ),
            )
        }));
    Ok(connection)
}
