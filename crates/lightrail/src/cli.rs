use std::{ffi::OsString, path::PathBuf, time::Duration};

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::{
    admin,
    commands::{init, profile},
    error::CliError,
    orchestrator::{self, DownOptions, LogOptions, PruneOptions, QueryOptions, UpOptions},
    output::{self, OutputFormat},
    plugin_host::{FLY_PLUGIN_ID, HETZNER_PLUGIN_ID, KUBERNETES_PLUGIN_ID, SSH_PLUGIN_ID},
    project::LoadedProject,
    workspace::ProjectPaths,
};

#[derive(Debug, Parser)]
#[command(
    name = "lightrail",
    version,
    about = "Agentless, isolated branch environments from Docker Compose",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Select a deployment profile where applicable; during init, name the first profile.
    #[arg(short = 'p', long, global = true, env = "LIGHTRAIL_PROFILE")]
    pub profile: Option<String>,

    /// Choose human, JSON, or compact plain output.
    #[arg(short = 'o', long, global = true, value_enum, default_value_t)]
    pub output: OutputFormat,

    /// Increase diagnostic verbosity (-vv for debug).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Discover Compose services and create lightrail.toml.
    Init(InitArgs),
    /// Manage named deployment profiles.
    Profile(ProfileArgs),
    /// Build and reconcile the current branch environment.
    Up(UpArgs),
    /// Show environment status and app URLs (`-o json` includes detailed state).
    Status(QueryArgs),
    /// Print public HTTPS app URLs (`-o plain` prints one URL per line).
    Urls(QueryArgs),
    /// Show or follow remote service logs (`-o json` emits JSON Lines).
    Logs(LogsArgs),
    /// Destroy isolated resources for the current environment.
    Down(DownArgs),
    /// Destroy expired environments visible through the selected profile.
    Prune(PruneArgs),
    /// Validate local tools and optionally the configured target.
    Doctor(DoctorArgs),
    /// Manage secret values stored outside project configuration.
    Secret(SecretArgs),
    /// Manage project-pinned executable plugins (run after `lightrail init`).
    Plugin(PluginArgs),
    /// Generate shell completion code.
    Completion { shell: Shell },
    /// Print the Lightrail version.
    Version,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Disable prompts; complete answers must come from --from.
    #[arg(long)]
    pub non_interactive: bool,

    /// TOML or JSON answers file; implies --non-interactive.
    #[arg(long, value_name = "FILE")]
    pub from: Option<PathBuf>,

    /// Select the deployment target without an extra prompt.
    #[arg(long, value_enum)]
    pub target: Option<init::TargetKind>,

    /// Select IP-DNS for SSH, Hetzner, or Kubernetes; Fly uses fly.dev.
    #[arg(
        long,
        value_name = "DOMAIN",
        value_parser = ["sslip.io", "nip.io"]
    )]
    pub domain: Option<String>,

    /// Recreate the config with the same project ID; destroy live environments first.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// Add a profile by copying the currently selected profile.
    Add {
        /// Name for the new profile.
        name: String,
        /// Profile to copy instead of the selected or default profile.
        #[arg(long, value_name = "PROFILE")]
        from: Option<String>,
    },
    /// List every configured profile.
    List,
    /// Show one profile.
    Show {
        /// Profile to show.
        name: String,
    },
    /// Remove a profile that has no live environments.
    Remove {
        /// Profile to remove.
        name: String,
    },
    /// Make a profile the project default.
    Default {
        /// Profile to use when --profile is omitted.
        name: String,
    },
}

#[derive(Debug, Args)]
pub struct UpArgs {
    /// Print the plan without making changes.
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Preserve failed resources for debugging; they may remain billable.
    #[arg(long)]
    pub keep_failed: bool,

    /// Maximum time to wait for the environment mutation lock.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    pub lock_timeout: Duration,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Query every project environment visible through the selected profile's target.
    #[arg(short = 'a', long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Compose service name; omit to show every service.
    pub service: Option<String>,

    /// Continue streaming new log records.
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Number of historical records to show.
    #[arg(long, default_value_t = 100)]
    pub tail: usize,
}

#[derive(Debug, Args)]
pub struct DownArgs {
    /// Destroy every project environment visible through the selected profile's target.
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Print the destruction plan without changing resources.
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Skip the interactive confirmation.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Bypass an unreachable machine lock for provider-owned machine deletion.
    #[arg(long)]
    pub force: bool,

    /// Maximum time to wait for the environment mutation lock.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    pub lock_timeout: Duration,
}

#[derive(Debug, Args)]
pub struct PruneArgs {
    /// Print the exact expired-environment plan without changing resources.
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Skip the interactive confirmation.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Maximum time to wait for the project mutation lock.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    pub lock_timeout: Duration,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Include target connectivity and credential checks.
    #[arg(long)]
    pub target: bool,
}

#[derive(Debug, Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Store or replace a project-scoped secret.
    Set {
        /// Secret reference name used by lightrail.toml.
        name: String,
        /// Read the value from stdin instead of an interactive prompt.
        #[arg(long)]
        stdin: bool,
    },
    /// List stored secret names without revealing values.
    List,
    /// Delete a stored secret.
    Delete {
        /// Secret name to delete.
        name: String,
    },
}

#[derive(Debug, Args)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub command: PluginCommand,
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Install and pin a plugin from a local path or HTTPS URL.
    Install {
        /// Executable path or HTTPS download URL.
        source: String,
    },
    /// Restore pinned plugins that are missing from the local cache.
    Sync,
    /// List pinned third-party plugins.
    List,
    /// Show a plugin manifest and pin details.
    Inspect {
        /// Stable plugin identifier.
        id: String,
    },
    /// Refresh one installed plugin from its pinned source.
    Update {
        /// Stable plugin identifier.
        id: String,
    },
    /// Remove one third-party plugin pin and cached executable.
    Remove {
        /// Stable plugin identifier.
        id: String,
    },
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(seconds) = value.strip_suffix('s') {
        (seconds, 1)
    } else if let Some(minutes) = value.strip_suffix('m') {
        (minutes, 60)
    } else {
        (value, 1)
    };
    let amount = number.parse::<u64>().map_err(|_| {
        format!("invalid duration `{value}`; use seconds (`30s`) or minutes (`2m`)")
    })?;
    amount
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration `{value}` is too large"))
}

pub async fn dispatch(cli: Cli) -> Result<(), CliError> {
    let selected_profile = cli.profile.clone();
    let format = cli.output;
    match cli.command {
        Command::Init(arguments) => {
            if arguments.non_interactive && arguments.from.is_none() {
                return Err(CliError::Usage(
                    "`init --non-interactive` requires `--from <FILE>` with complete target answers"
                        .into(),
                ));
            }
            let start = std::env::current_dir()?;
            let summary = init::run(init::InitOptions {
                start,
                profile: selected_profile
                    .clone()
                    .unwrap_or_else(|| "preview".to_owned()),
                target: arguments.target,
                dns_domain: arguments.domain,
                non_interactive: arguments.non_interactive || arguments.from.is_some(),
                answers_file: arguments.from,
                force: arguments.force,
            })
            .await?;
            print_init_summary(&summary, format)
        }
        Command::Profile(arguments) => {
            let paths = ProjectPaths::discover(&std::env::current_dir()?)?;
            match arguments.command {
                ProfileCommand::Add { name, from } => {
                    let template = from.as_deref().or(selected_profile.as_deref());
                    let mutation = profile::add(&paths.config, &name, template).await?;
                    render_value(&mutation, format, format!("added profile `{name}`"))
                }
                ProfileCommand::List => {
                    let config = profile::load(&paths.config)?;
                    let profiles = profile::list(&config);
                    match format {
                        OutputFormat::Json => output::json(&profiles),
                        OutputFormat::Plain => {
                            for item in profiles {
                                output::line(item.name)?;
                            }
                            Ok(())
                        }
                        OutputFormat::Human => {
                            for item in profiles {
                                output::line(format!(
                                    "{:<20} {:<9} {}",
                                    format!(
                                        "{}{}",
                                        item.name,
                                        if item.is_default { " (default)" } else { "" }
                                    ),
                                    isolation_name(item.isolation),
                                    target_name(&item.target_plugin),
                                ))?;
                            }
                            Ok(())
                        }
                    }
                }
                ProfileCommand::Show { name } => {
                    let config = profile::load(&paths.config)?;
                    let selected = profile::show(&config, &name)?;
                    match format {
                        OutputFormat::Json => output::json(&selected),
                        OutputFormat::Plain => {
                            output::line(toml::to_string_pretty(&selected.profile)?)
                        }
                        OutputFormat::Human => {
                            output::line(format!(
                                "{}{}",
                                selected.name,
                                if selected.is_default {
                                    " (default)"
                                } else {
                                    ""
                                }
                            ))?;
                            output::line(format!(
                                "  isolation  {}\n  target     {}\n  apps       {}",
                                isolation_name(selected.profile.isolation),
                                target_name(selected.profile.pipeline.target.as_str()),
                                selected.profile.apps.join(", ")
                            ))
                        }
                    }
                }
                ProfileCommand::Remove { name } => {
                    let project = LoadedProject::discover(Some(&name))?;
                    let live = orchestrator::live_environment_count(project).await?;
                    let mutation = profile::remove(&paths.config, &name, live).await?;
                    render_value(&mutation, format, format!("removed profile `{name}`"))
                }
                ProfileCommand::Default { name } => {
                    let mutation = profile::set_default(&paths.config, &name).await?;
                    render_value(
                        &mutation,
                        format,
                        format!("default profile is now `{name}`"),
                    )
                }
            }
        }
        Command::Up(arguments) => {
            let project = LoadedProject::discover(selected_profile.as_deref())?;
            orchestrator::up(
                project,
                UpOptions {
                    dry_run: arguments.dry_run,
                    keep_failed: arguments.keep_failed,
                    lock_timeout: arguments.lock_timeout,
                    output: format,
                },
            )
            .await?;
            Ok(())
        }
        Command::Status(arguments) => {
            let project = LoadedProject::discover(selected_profile.as_deref())?;
            orchestrator::query(
                project,
                QueryOptions {
                    all: arguments.all,
                    output: format,
                },
                false,
            )
            .await?;
            Ok(())
        }
        Command::Urls(arguments) => {
            let project = LoadedProject::discover(selected_profile.as_deref())?;
            orchestrator::query(
                project,
                QueryOptions {
                    all: arguments.all,
                    output: format,
                },
                true,
            )
            .await?;
            Ok(())
        }
        Command::Logs(arguments) => {
            let project = LoadedProject::discover(selected_profile.as_deref())?;
            orchestrator::logs(
                project,
                LogOptions {
                    service: arguments.service,
                    follow: arguments.follow,
                    tail: arguments.tail,
                    output: format,
                },
            )
            .await
        }
        Command::Down(arguments) => {
            let project = LoadedProject::discover(selected_profile.as_deref())?;
            orchestrator::down(
                project,
                DownOptions {
                    all: arguments.all,
                    dry_run: arguments.dry_run,
                    yes: arguments.yes,
                    force: arguments.force,
                    lock_timeout: arguments.lock_timeout,
                    output: format,
                },
            )
            .await
        }
        Command::Prune(arguments) => {
            let project = LoadedProject::discover(selected_profile.as_deref())?;
            orchestrator::prune(
                project,
                PruneOptions {
                    dry_run: arguments.dry_run,
                    yes: arguments.yes,
                    lock_timeout: arguments.lock_timeout,
                    output: format,
                },
            )
            .await
        }
        Command::Doctor(arguments) => {
            let report =
                admin::doctor(format, arguments.target, selected_profile.as_deref()).await?;
            crate::doctor::ensure_healthy(&report)
        }
        Command::Secret(arguments) => admin::secret(arguments.command, format).await,
        Command::Plugin(arguments) => admin::plugin(arguments.command, format).await,
        Command::Completion { shell } => {
            let mut command = Cli::command();
            clap_complete::generate(shell, &mut command, "lightrail", &mut std::io::stdout());
            Ok(())
        }
        Command::Version => output::line(env!("CARGO_PKG_VERSION")),
    }
}

fn print_init_summary(summary: &init::InitSummary, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(summary),
        OutputFormat::Plain => output::line(summary.config_path.display()),
        OutputFormat::Human => {
            output::line(format!("Initialized `{}`", summary.project_slug))?;
            output::line(format!("  config   {}", summary.config_path.display()))?;
            output::line(format!("  profile  {}", summary.profile))?;
            output::line(format!(
                "  target   {} ({} isolation)",
                summary.target,
                isolation_name(summary.isolation)
            ))?;
            if let Some(detail) = &summary.target_detail {
                output::line(format!("           {detail}"))?;
            }
            match summary.target {
                init::TargetKind::Fly => {
                    output::line(format!(
                        "  dns      {} (provider native)",
                        summary.dns_domain
                    ))?;
                }
                init::TargetKind::Kubernetes => {
                    output::line(format!(
                        "  dns      {} (ingress IPv4 encoded as hex)",
                        summary.dns_domain
                    ))?;
                }
                init::TargetKind::Ssh | init::TargetKind::Hetzner => {
                    output::line(format!("  dns      {} (hex IPv4)", summary.dns_domain))?;
                }
            }
            output::line("  apps")?;
            for app in &summary.apps {
                output::line(format!("    {:<16} {}:{}", app.name, app.service, app.port))?;
            }
            output::line("")?;
            output::line("Next: lightrail up --dry-run")?;
            match summary.target {
                init::TargetKind::Hetzner => {
                    output::line(
                        "  `up` asks once for `hetzner-token`; run `lightrail secret set hetzner-token` to store it for reuse.",
                    )?;
                }
                init::TargetKind::Fly => {
                    output::line(
                        "  `up` asks once for `fly-token`; run `lightrail secret set fly-token` to store it for reuse.",
                    )?;
                }
                init::TargetKind::Kubernetes => {
                    output::line(
                        "  Ensure the control namespace, IngressClass, ClusterIssuer, and optional image-pull Secret already exist.",
                    )?;
                }
                init::TargetKind::Ssh => {}
            }
            output::line("  Then deploy: lightrail up")
        }
    }
}

const fn isolation_name(isolation: lightrail_core::Isolation) -> &'static str {
    match isolation {
        lightrail_core::Isolation::Project => "project",
        lightrail_core::Isolation::Environment => "environment",
        lightrail_core::Isolation::Machine => "machine",
    }
}

fn target_name(plugin_id: &str) -> &str {
    match plugin_id {
        SSH_PLUGIN_ID => "Generic SSH host",
        HETZNER_PLUGIN_ID => "Hetzner Cloud",
        KUBERNETES_PLUGIN_ID => "Kubernetes",
        FLY_PLUGIN_ID => "Fly.io",
        other => other,
    }
}

fn render_value<T: serde::Serialize>(
    value: &T,
    format: OutputFormat,
    human: String,
) -> Result<(), CliError> {
    match format {
        OutputFormat::Json => output::json(value),
        OutputFormat::Plain | OutputFormat::Human => output::line(human),
    }
}

pub fn try_parse_from<I, T>(arguments: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile_and_up_options() {
        let cli = try_parse_from([
            "lightrail",
            "--profile",
            "preview",
            "--output",
            "json",
            "up",
            "--dry-run",
            "--lock-timeout",
            "2m",
        ])
        .expect("parse");
        assert_eq!(cli.profile.as_deref(), Some("preview"));
        assert_eq!(cli.output, OutputFormat::Json);
        let Command::Up(up) = cli.command else {
            panic!("expected up");
        };
        assert!(up.dry_run);
        assert_eq!(up.lock_timeout, Duration::from_secs(120));
    }

    #[test]
    fn init_profile_has_one_meaning_before_or_after_the_subcommand() {
        let before = try_parse_from(["lightrail", "--profile", "staging", "init"]).expect("before");
        let after = try_parse_from(["lightrail", "init", "--profile", "staging"]).expect("after");

        assert_eq!(before.profile.as_deref(), Some("staging"));
        assert_eq!(after.profile.as_deref(), Some("staging"));
        assert!(matches!(before.command, Command::Init(_)));
        assert!(matches!(after.command, Command::Init(_)));
    }

    #[test]
    fn init_accepts_direct_target_and_domain_choices() {
        let cli = try_parse_from([
            "lightrail",
            "init",
            "--target",
            "hetzner",
            "--domain",
            "nip.io",
        ])
        .expect("init choices");
        let Command::Init(init) = cli.command else {
            panic!("expected init");
        };

        assert_eq!(init.target, Some(init::TargetKind::Hetzner));
        assert_eq!(init.domain.as_deref(), Some("nip.io"));
        assert!(
            try_parse_from(["lightrail", "init", "--domain", "example.com"]).is_err(),
            "custom DNS providers are intentionally unsupported"
        );
        let kubernetes =
            try_parse_from(["lightrail", "init", "--target", "kubernetes"]).expect("Kubernetes");
        assert!(matches!(
            kubernetes.command,
            Command::Init(InitArgs {
                target: Some(init::TargetKind::Kubernetes),
                ..
            })
        ));
        let fly = try_parse_from(["lightrail", "init", "--target", "fly"]).expect("Fly");
        assert!(matches!(
            fly.command,
            Command::Init(InitArgs {
                target: Some(init::TargetKind::Fly),
                ..
            })
        ));
    }

    #[test]
    fn common_short_options_are_available() {
        let cli = try_parse_from(["lightrail", "-p", "preview", "-o", "plain", "up", "-n"])
            .expect("short options");

        assert_eq!(cli.profile.as_deref(), Some("preview"));
        assert_eq!(cli.output, OutputFormat::Plain);
        let Command::Up(up) = cli.command else {
            panic!("expected up");
        };
        assert!(up.dry_run);
    }

    #[test]
    fn parses_safe_prune_options() {
        let cli = try_parse_from([
            "lightrail",
            "--profile",
            "preview",
            "prune",
            "--dry-run",
            "--lock-timeout",
            "2m",
        ])
        .expect("prune");
        let Command::Prune(prune) = cli.command else {
            panic!("expected prune");
        };

        assert!(prune.dry_run);
        assert!(!prune.yes);
        assert_eq!(prune.lock_timeout, Duration::from_secs(120));
    }

    #[test]
    fn usage_does_not_exist() {
        assert!(try_parse_from(["lightrail", "usage"]).is_err());
    }

    #[test]
    fn rejects_overflowing_lock_durations() {
        assert!(
            try_parse_from(["lightrail", "up", "--lock-timeout", "18446744073709551615m",])
                .is_err()
        );
    }
}
