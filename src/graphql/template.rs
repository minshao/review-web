use super::{ParseEnumError, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Enum, InputObject, Object, Result, SimpleObject, Union,
};
use bincode::Options;
use review_database::{IterableMap, Map, MapIterator, Store};
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    sync::Arc,
};

#[derive(Default)]
pub(super) struct TemplateQuery;

#[Object]
impl TemplateQuery {
    /// A list of model templates.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn template_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Template, TemplateTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last) },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct TemplateMutation;

#[Object]
impl TemplateMutation {
    /// Inserts a new template, overwriting any existing template with the same
    /// name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_template(
        &self,
        ctx: &Context<'_>,
        structured: Option<StructuredClusteringTemplateInput>,
        unstructured: Option<UnstructuredClusteringTemplateInput>,
    ) -> Result<String> {
        let template = match (structured, unstructured) {
            (Some(structured), None) => Template::Structured(
                structured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?,
            ),
            (None, Some(unstructured)) => Template::Unstructured(
                unstructured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?,
            ),
            (Some(_), Some(_)) => {
                return Err(
                    "cannot specify both structured and unstructured clustering algorithms".into(),
                );
            }
            (None, None) => {
                return Err(
                    "must specify either structured or unstructured clustering algorithms".into(),
                );
            }
        };

        let name = template.name().to_string();
        let value = bincode::DefaultOptions::new().serialize(&template)?;
        let map = ctx.data::<Arc<Store>>()?.template_map();
        map.put(name.as_bytes(), &value)?;
        Ok(name)
    }

    /// Removes a template, returning the name of the removed template if it no
    /// longer exists.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_template(&self, ctx: &Context<'_>, name: String) -> Result<String> {
        let map = ctx.data::<Arc<Store>>()?.template_map();
        map.delete(name.as_bytes())?;
        Ok(name)
    }

    /// Updates the given template.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_template(
        &self,
        ctx: &Context<'_>,
        old_structured: Option<StructuredClusteringTemplateInput>,
        old_unstructured: Option<UnstructuredClusteringTemplateInput>,
        new_structured: Option<StructuredClusteringTemplateInput>,
        new_unstructured: Option<UnstructuredClusteringTemplateInput>,
    ) -> Result<bool> {
        match (
            old_structured,
            old_unstructured,
            new_structured,
            new_unstructured,
        ) {
            (Some(old_structured), None, Some(new_structured), None) => {
                let old_template = Template::Structured(
                    old_structured
                        .try_into()
                        .map_err(|_| "invalid clustering algorithm")?,
                );
                let new_template = Template::Structured(
                    new_structured
                        .try_into()
                        .map_err(|_| "invalid clustering algorithm")?,
                );

                let old_key = old_template.name().as_bytes();
                let old_value = bincode::DefaultOptions::new().serialize(&old_template)?;
                let new_key = new_template.name().as_bytes();
                let new_value = bincode::DefaultOptions::new().serialize(&new_template)?;
                let map = ctx.data::<Arc<Store>>()?.template_map();
                map.update((old_key, &old_value), (new_key, &new_value))?;
            }
            (None, Some(old_unstructured), None, Some(new_unstructured)) => {
                let old_template = Template::Unstructured(
                    old_unstructured
                        .try_into()
                        .map_err(|_| "invalid clustering algorithm")?,
                );
                let new_template = Template::Unstructured(
                    new_unstructured
                        .try_into()
                        .map_err(|_| "invalid clustering algorithm")?,
                );

                let old_key = old_template.name().as_bytes();
                let old_value = bincode::DefaultOptions::new().serialize(&old_template)?;
                let new_key = new_template.name().as_bytes();
                let new_value = bincode::DefaultOptions::new().serialize(&new_template)?;
                let map = ctx.data::<Arc<Store>>()?.template_map();
                map.update((old_key, &old_value), (new_key, &new_value))?;
            }
            _ => {
                return Err(
                    "cannot specify both old_structured and new_structured, or old_unstructured and new_unstructured".into(),
                );
            }
        };
        Ok(true)
    }
}

#[derive(InputObject)]
struct StructuredClusteringTemplateInput {
    name: String,
    description: Option<String>,
    algorithm: Option<StructuredClusteringAlgorithm>, // DBSCAN or OPTICS (default)
    eps: Option<f32>,
    format: Option<String>,
    time_intervals: Option<Vec<i64>>,
    numbers_of_top_n: Option<Vec<i32>>,
}

#[derive(Copy, Clone, Deserialize, Enum, Eq, PartialEq, Serialize)]
enum StructuredClusteringAlgorithm {
    Dbscan,
    Optics,
}

#[derive(InputObject)]
struct UnstructuredClusteringTemplateInput {
    name: String,
    description: Option<String>,
    algorithm: Option<UnstructuredClusteringAlgorithm>, // PREFIX (default) or DISTRIBUTION
    min_token_length: Option<i32>,
}

#[derive(Deserialize, Serialize, Union)]
enum Template {
    Structured(StructuredClusteringTemplate),
    Unstructured(UnstructuredClusteringTemplate),
}

impl Template {
    fn name(&self) -> &str {
        match self {
            Template::Structured(template) => &template.name,
            Template::Unstructured(template) => &template.name,
        }
    }
}

#[derive(Copy, Clone, Deserialize, Enum, Eq, PartialEq, Serialize)]
enum UnstructuredClusteringAlgorithm {
    Prefix,
    Distribution,
}

#[derive(Deserialize, Serialize, SimpleObject)]
struct StructuredClusteringTemplate {
    name: String,
    description: String,
    algorithm: Option<StructuredClusteringAlgorithm>,
    eps: Option<f32>,
    format: Option<String>,
    time_intervals: Option<Vec<i64>>,
    numbers_of_top_n: Option<Vec<i32>>,
}

impl TryFrom<StructuredClusteringTemplateInput> for StructuredClusteringTemplate {
    type Error = ParseEnumError;

    fn try_from(input: StructuredClusteringTemplateInput) -> Result<Self, Self::Error> {
        Ok(Self {
            name: input.name,
            description: input.description.unwrap_or_default(),
            algorithm: input.algorithm,
            eps: input.eps,
            format: input.format,
            time_intervals: input.time_intervals,
            numbers_of_top_n: input.numbers_of_top_n,
        })
    }
}

#[derive(Deserialize, Serialize, SimpleObject)]
struct UnstructuredClusteringTemplate {
    name: String,
    description: String,
    algorithm: Option<UnstructuredClusteringAlgorithm>,
    min_token_length: Option<i32>,
}

impl TryFrom<UnstructuredClusteringTemplateInput> for UnstructuredClusteringTemplate {
    type Error = ParseEnumError;

    fn try_from(input: UnstructuredClusteringTemplateInput) -> Result<Self, Self::Error> {
        Ok(Self {
            name: input.name,
            description: input.description.unwrap_or_default(),
            algorithm: input.algorithm,
            min_token_length: input.min_token_length,
        })
    }
}

struct TemplateTotalCount;

#[Object]
impl TemplateTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let map = ctx.data::<Arc<Store>>()?.template_map();
        let count = map.iter_forward()?.count();
        Ok(count)
    }
}

fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Template, TemplateTotalCount, EmptyFields>> {
    let map = ctx.data::<Arc<Store>>()?.template_map();
    super::load::<'_, Map, MapIterator, Template, Template, TemplateTotalCount>(
        &map,
        after,
        before,
        first,
        last,
        TemplateTotalCount,
    )
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_template() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 0}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertTemplate(unstructured: {
                        name: "t1",
                        description: "test",
                        algorithm: "PREFIX",
                        minTokenLength: 1
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTemplate: "t1"}"#);

        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 1}}"#);

        let res = schema
            .execute(
                r#"{
                templateList {
                    edges {
                        node {
                            ... on UnstructuredClusteringTemplate {
                                name
                            }
                        }
                    }
                totalCount
            }
        }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{templateList: {edges: [{node: {name: "t1"}}],totalCount: 1}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                updateTemplate(oldUnstructured: {
                    name: "t1",
                    description: "test",
                    algorithm: "PREFIX",
                    minTokenLength: 1
                },
                newUnstructured: {
                    name: "t1",
                    description: "test",
                    algorithm: "DISTRIBUTION",
                    minTokenLength: 2
                })
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTemplate: true}"#);

        let res = schema
            .execute(
                r#"{
                templateList {
                    edges {
                        node {
                            ... on UnstructuredClusteringTemplate {
                                algorithm
                            }
                        }
                    }
                totalCount
            }
        }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{templateList: {edges: [{node: {algorithm: DISTRIBUTION}}],totalCount: 1}}"#
        );

        let res = schema
            .execute(r#"mutation { removeTemplate(name: "t1") }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeTemplate: "t1"}"#);

        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 0}}"#);
    }
}
