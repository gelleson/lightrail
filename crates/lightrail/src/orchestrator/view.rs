//! Stable orchestration views, observation aggregation, and CLI rendering.

use std::collections::BTreeMap;

use lightrail_plugin_protocol::{Endpoint, InspectResult, LogRecord, ResourceStatus};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    error::CliError,
    output::{self, OutputFormat},
};

#[derive(Clone, Debug, Serialize)]
pub struct PlanView {
    pub environment_id: String,
    pub branch: String,
    pub profile: String,
    pub operation: &'static str,
    pub has_changes: bool,
    pub plugins: Vec<PluginPlanView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PluginPlanView {
    pub capability: String,
    pub plugin: String,
    pub plan_id: String,
    pub has_changes: bool,
    pub actions: Vec<ActionView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActionView {
    pub id: String,
    pub summary: String,
    pub destructive: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnvironmentView {
    pub environment_id: String,
    pub branch: String,
    pub profile: String,
    pub status: ResourceStatus,
    pub endpoints: Vec<Endpoint>,
    pub plugins: Vec<PluginStatusView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<EnvironmentSummaryView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnvironmentSummaryView {
    pub environment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub status: ResourceStatus,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PluginStatusView {
    pub capability: String,
    pub plugin: String,
    pub status: ResourceStatus,
    pub state: Value,
}

pub(super) fn combined_status(statuses: impl Iterator<Item = ResourceStatus>) -> ResourceStatus {
    let mut saw_any = false;
    let mut worst = ResourceStatus::Ready;
    for status in statuses {
        saw_any = true;
        if status_rank(status) > status_rank(worst) {
            worst = status;
        }
    }
    if saw_any {
        worst
    } else {
        ResourceStatus::Absent
    }
}

const fn status_rank(status: ResourceStatus) -> u8 {
    match status {
        ResourceStatus::Ready => 0,
        ResourceStatus::Absent => 1,
        ResourceStatus::Pending => 2,
        ResourceStatus::Destroying => 3,
        ResourceStatus::Degraded => 4,
        ResourceStatus::Unknown => 5,
    }
}

pub(super) fn collect_endpoints<'a>(
    inspections: impl Iterator<Item = &'a InspectResult>,
) -> Vec<Endpoint> {
    let mut endpoints = BTreeMap::new();
    for endpoint in inspections.flat_map(|inspection| &inspection.endpoints) {
        endpoints.insert(endpoint.url.clone(), endpoint.clone());
    }
    endpoints.into_values().collect()
}

pub(super) fn collect_environment_summaries<'a>(
    inspections: impl Iterator<Item = &'a InspectResult>,
) -> Vec<EnvironmentSummaryView> {
    let inspections = inspections.collect::<Vec<_>>();
    let mut environments = BTreeMap::<String, EnvironmentSummaryView>::new();
    for inspection in &inspections {
        let Some(items) = inspection
            .state
            .get("environments")
            .and_then(Value::as_array)
        else {
            continue;
        };
        for item in items {
            let (environment_id, branch, profile, status, endpoints) =
                if let Some(environment_id) = item.as_str() {
                    (
                        environment_id.to_owned(),
                        None,
                        None,
                        ResourceStatus::Unknown,
                        Vec::new(),
                    )
                } else {
                    let Some(environment_id) = item
                        .get("environment_id")
                        .or_else(|| item.get("id"))
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let status = item
                        .get("status")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                        .unwrap_or(inspection.status);
                    let endpoints = item
                        .get("endpoints")
                        .cloned()
                        .and_then(|value| serde_json::from_value(value).ok())
                        .unwrap_or_default();
                    (
                        environment_id.to_owned(),
                        item.get("branch")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("profile")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        status,
                        endpoints,
                    )
                };
            let candidate = EnvironmentSummaryView {
                environment_id: environment_id.clone(),
                branch,
                profile,
                status,
                endpoints,
            };
            environments
                .entry(environment_id)
                .and_modify(|existing| merge_environment_summary(existing, &candidate))
                .or_insert(candidate);
        }
    }
    // Machine-isolated providers may be able to rediscover servers even when
    // an individual runtime is not reachable. Preserve that visibility
    // without claiming branch names or URLs that were not observed.
    if environments.is_empty() {
        for inspection in inspections {
            let Some(targets) = inspection.state.get("targets").and_then(Value::as_array) else {
                continue;
            };
            for target in targets {
                let environment_id = target
                    .get("environment_id")
                    .and_then(Value::as_str)
                    .or_else(|| target.get("environment_label").and_then(Value::as_str))
                    .map(ToOwned::to_owned)
                    .or_else(|| {
                        target
                            .get("server_id")
                            .and_then(Value::as_u64)
                            .map(|id| format!("hetzner-server-{id}"))
                    });
                let Some(environment_id) = environment_id else {
                    continue;
                };
                let status = match target.get("server_status").and_then(Value::as_str) {
                    Some("running") => ResourceStatus::Ready,
                    Some("initializing" | "starting" | "migrating" | "rebuilding") => {
                        ResourceStatus::Pending
                    }
                    Some(_) => ResourceStatus::Degraded,
                    None => inspection.status,
                };
                environments.insert(
                    environment_id.clone(),
                    EnvironmentSummaryView {
                        environment_id,
                        branch: None,
                        profile: None,
                        status,
                        endpoints: Vec::new(),
                    },
                );
            }
        }
    }
    environments.into_values().collect()
}

fn merge_environment_summary(
    existing: &mut EnvironmentSummaryView,
    candidate: &EnvironmentSummaryView,
) {
    if existing.branch.is_none() {
        existing.branch.clone_from(&candidate.branch);
    }
    if existing.profile.is_none() {
        existing.profile.clone_from(&candidate.profile);
    }
    if existing.status == ResourceStatus::Unknown
        || (candidate.status != ResourceStatus::Unknown
            && status_rank(candidate.status) > status_rank(existing.status))
    {
        existing.status = candidate.status;
    }
    let mut endpoints = existing
        .endpoints
        .iter()
        .cloned()
        .map(|endpoint| (endpoint.url.clone(), endpoint))
        .collect::<BTreeMap<_, _>>();
    for endpoint in &candidate.endpoints {
        endpoints.insert(endpoint.url.clone(), endpoint.clone());
    }
    existing.endpoints = endpoints.into_values().collect();
}

pub(super) fn print_plan(plan: &PlanView, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(plan),
        OutputFormat::Plain => {
            output::line(format!(
                "{} {} ({}/{})",
                plan.operation, plan.environment_id, plan.branch, plan.profile
            ))?;
            for plugin in &plan.plugins {
                if plugin.actions.is_empty() {
                    continue;
                }
                for action in &plugin.actions {
                    output::line(format!(
                        "  {:<9} {}{}",
                        plugin.capability,
                        action.summary,
                        if action.destructive {
                            " [destructive]"
                        } else {
                            ""
                        }
                    ))?;
                }
            }
            Ok(())
        }
        OutputFormat::Human => print_human_lines(render_human_plan(plan)),
    }
}

fn render_human_plan(plan: &PlanView) -> Vec<String> {
    let mut lines = vec![format!(
        "Plan: {} {} / {}",
        plan.operation, plan.branch, plan.profile
    )];
    if !plan.has_changes {
        lines.push("  No changes".into());
        return lines;
    }

    for action in plan.plugins.iter().flat_map(|plugin| &plugin.actions) {
        lines.push(format!(
            "  - {}{}",
            action.summary,
            if action.destructive {
                " [destructive]"
            } else {
                ""
            }
        ));
    }
    if lines.len() == 1 {
        lines.push("  Changes reported; use -o json for plugin details".into());
    }
    lines
}

pub(super) fn print_environment(
    environment: &EnvironmentView,
    format: OutputFormat,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(environment),
        OutputFormat::Plain => {
            if !environment.environments.is_empty() {
                for discovered in &environment.environments {
                    output::line(format!(
                        "{}\t{}",
                        discovered.environment_id,
                        format!("{:?}", discovered.status).to_ascii_lowercase()
                    ))?;
                    for endpoint in &discovered.endpoints {
                        output::line(&endpoint.url)?;
                    }
                }
                return Ok(());
            }
            output::line(format!("{:?}", environment.status).to_ascii_lowercase())?;
            for endpoint in &environment.endpoints {
                output::line(&endpoint.url)?;
            }
            Ok(())
        }
        OutputFormat::Human => print_human_lines(render_human_environment(environment)),
    }
}

fn render_human_environment(environment: &EnvironmentView) -> Vec<String> {
    let mut lines = Vec::new();
    if !environment.environments.is_empty() {
        for discovered in &environment.environments {
            push_human_environment(
                &mut lines,
                &discovered.environment_id,
                discovered.branch.as_deref(),
                discovered.profile.as_deref(),
                discovered.status,
                &discovered.endpoints,
            );
        }
        return lines;
    }

    push_human_environment(
        &mut lines,
        &environment.environment_id,
        Some(&environment.branch),
        Some(&environment.profile),
        environment.status,
        &environment.endpoints,
    );
    lines
}

fn push_human_environment(
    lines: &mut Vec<String>,
    environment_id: &str,
    branch: Option<&str>,
    profile: Option<&str>,
    status: ResourceStatus,
    endpoints: &[Endpoint],
) {
    lines.push(format!(
        "{}  {}",
        human_environment_label(environment_id, branch, profile),
        human_status(status)
    ));
    for endpoint in endpoints {
        lines.push(format!("  {:<16} {}", endpoint.app, endpoint.url));
    }
    if status == ResourceStatus::Absent {
        lines.push("  Next: run lightrail up".into());
    }
}

fn human_environment_label(
    environment_id: &str,
    branch: Option<&str>,
    profile: Option<&str>,
) -> String {
    match (known_label(branch), known_label(profile)) {
        (Some(branch), Some(profile)) => format!("{branch} / {profile}"),
        _ => environment_id.to_owned(),
    }
}

fn known_label(value: Option<&str>) -> Option<&str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "unknown")
}

const fn human_status(status: ResourceStatus) -> &'static str {
    match status {
        ResourceStatus::Absent => "absent",
        ResourceStatus::Pending => "pending",
        ResourceStatus::Ready => "ready",
        ResourceStatus::Degraded => "degraded",
        ResourceStatus::Destroying => "destroying",
        ResourceStatus::Unknown => "unknown",
    }
}

fn print_human_lines(lines: Vec<String>) -> Result<(), CliError> {
    for line in lines {
        output::line(line)?;
    }
    Ok(())
}

pub(super) fn print_urls(
    environment: &EnvironmentView,
    format: OutputFormat,
) -> Result<(), CliError> {
    let aggregate_urls = environment
        .environments
        .iter()
        .flat_map(|environment| {
            environment.endpoints.iter().map(move |endpoint| {
                json!({
                    "environment_id": environment.environment_id,
                    "branch": environment.branch,
                    "profile": environment.profile,
                    "app": endpoint.app,
                    "url": endpoint.url,
                })
            })
        })
        .collect::<Vec<_>>();
    if environment.endpoints.is_empty() && aggregate_urls.is_empty() {
        return Err(CliError::Operation(
            "environment has no discoverable public URLs; run `lightrail up` to create or update \
             it, or `lightrail status` to inspect it"
                .into(),
        ));
    }
    match format {
        OutputFormat::Json if aggregate_urls.is_empty() => output::json(&environment.endpoints),
        OutputFormat::Json => output::json(&aggregate_urls),
        OutputFormat::Plain => {
            if aggregate_urls.is_empty() {
                for endpoint in &environment.endpoints {
                    output::line(&endpoint.url)?;
                }
            } else {
                for url in &aggregate_urls {
                    if let Some(url) = url.get("url").and_then(Value::as_str) {
                        output::line(url)?;
                    }
                }
            }
            Ok(())
        }
        OutputFormat::Human => {
            if aggregate_urls.is_empty() {
                for endpoint in &environment.endpoints {
                    output::line(format!("{:<16} {}", endpoint.app, endpoint.url))?;
                }
            } else {
                for url in &aggregate_urls {
                    let branch = url
                        .get("branch")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let app = url.get("app").and_then(Value::as_str).unwrap_or("app");
                    let endpoint = url.get("url").and_then(Value::as_str).unwrap_or_default();
                    output::line(format!("{branch}/{app:<16} {endpoint}"))?;
                }
            }
            Ok(())
        }
    }
}

pub(super) fn print_log_records(
    records: &[LogRecord],
    format: OutputFormat,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => {
            for record in records {
                output::json_line(record)?;
            }
            Ok(())
        }
        OutputFormat::Plain => {
            for record in records {
                output::line(&record.line)?;
            }
            Ok(())
        }
        OutputFormat::Human => {
            for record in records {
                output::line(format!("{:<16} {}", record.service, record.line))?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_plan_lists_actions_without_engine_ids() {
        let plan = PlanView {
            environment_id: "lr-opaque-id".into(),
            branch: "feature-login".into(),
            profile: "preview".into(),
            operation: "up",
            has_changes: true,
            plugins: vec![PluginPlanView {
                capability: "target".into(),
                plugin: "dev.lightrail.target.hetzner".into(),
                plan_id: "internal-plan-id".into(),
                has_changes: true,
                actions: vec![
                    ActionView {
                        id: "create-server".into(),
                        summary: "Create server".into(),
                        destructive: false,
                    },
                    ActionView {
                        id: "remove-route".into(),
                        summary: "Remove old route".into(),
                        destructive: true,
                    },
                ],
            }],
        };

        assert_eq!(
            render_human_plan(&plan),
            vec![
                "Plan: up feature-login / preview",
                "  - Create server",
                "  - Remove old route [destructive]",
            ]
        );
    }

    #[test]
    fn human_plan_has_one_concise_no_change_line() {
        let plan = PlanView {
            environment_id: "lr-opaque-id".into(),
            branch: "main".into(),
            profile: "preview".into(),
            operation: "up",
            has_changes: false,
            plugins: vec![
                PluginPlanView {
                    capability: "source".into(),
                    plugin: "dev.lightrail.source.compose".into(),
                    plan_id: "source-plan".into(),
                    has_changes: false,
                    actions: Vec::new(),
                },
                PluginPlanView {
                    capability: "runtime".into(),
                    plugin: "dev.lightrail.runtime.compose".into(),
                    plan_id: "runtime-plan".into(),
                    has_changes: false,
                    actions: Vec::new(),
                },
            ],
        };

        assert_eq!(
            render_human_plan(&plan),
            vec!["Plan: up main / preview", "  No changes"]
        );
    }

    #[test]
    fn human_plan_explains_changes_without_action_details() {
        let plan = PlanView {
            environment_id: "lr-opaque-id".into(),
            branch: "main".into(),
            profile: "preview".into(),
            operation: "up",
            has_changes: true,
            plugins: vec![PluginPlanView {
                capability: "target".into(),
                plugin: "third.party.target".into(),
                plan_id: "opaque-plan".into(),
                has_changes: true,
                actions: Vec::new(),
            }],
        };

        assert_eq!(
            render_human_plan(&plan),
            vec![
                "Plan: up main / preview",
                "  Changes reported; use -o json for plugin details",
            ]
        );
    }

    #[test]
    fn human_environment_prefers_branch_and_profile_over_opaque_id() {
        let environment = EnvironmentView {
            environment_id: "lr-opaque-id".into(),
            branch: "feature-login".into(),
            profile: "preview".into(),
            status: ResourceStatus::Ready,
            endpoints: vec![Endpoint {
                app: "web".into(),
                url: "https://web.example.test".into(),
            }],
            plugins: Vec::new(),
            environments: Vec::new(),
        };

        assert_eq!(
            render_human_environment(&environment),
            vec![
                "feature-login / preview  ready",
                &format!("  {:<16} {}", "web", "https://web.example.test"),
            ]
        );
    }

    #[test]
    fn human_environment_uses_id_fallback_and_guides_absent_environment() {
        let environment = EnvironmentView {
            environment_id: "aggregate".into(),
            branch: String::new(),
            profile: String::new(),
            status: ResourceStatus::Unknown,
            endpoints: Vec::new(),
            plugins: Vec::new(),
            environments: vec![EnvironmentSummaryView {
                environment_id: "lr-discovered-id".into(),
                branch: None,
                profile: None,
                status: ResourceStatus::Absent,
                endpoints: Vec::new(),
            }],
        };

        assert_eq!(
            render_human_environment(&environment),
            vec!["lr-discovered-id  absent", "  Next: run lightrail up",]
        );
    }
}
