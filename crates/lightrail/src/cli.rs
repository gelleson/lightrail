use std::{ffi::OsString, path::PathBuf, time::Duration};

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use crate::{
    admin,
    commands::{init, profile},
    error::CliError,
    orchestrator::{self, DownOptions, LogOptions, QueryOptions, UpOptions},
    output::{self, OutputFormat},
    project::LoadedProject,
    workspace::ProjectPaths,
};

#[derive(Debug, Parser)]
#[command(
    name = "lightrail",
    version,
    about = "Agentless, isolated branch environments from Docker Compose",
    propagate_version = true
)]
pub struct Cli {
    /// Select a named profile (overrides `LIGHTRAIL_PROFILE` and project default).
    #[arg(long, global = true, env = "LIGHTRAIL_PROFILE")]
    pub profile: Option<String>,

    /// Choose human, JSON, or plain output.
    #[arg(long, global = true, value_enum, default_value_t)]
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
    /// Rediscover the current environment.
    Status(QueryArgs),
    /// Print public HTTPS application URLs.
    Urls(QueryArgs),
    /// Stream remote service logs.
    Logs(LogsArgs),
    /// Destroy isolated resources for the current environment.
    Down(DownArgs),
    /// Validate local tools, plugins, credentials, and target access.
    Doctor(DoctorArgs),
    /// Manage secret values stored outside project configuration.
    Secret(SecretArgs),
    /// Manage executable plugins.
    Plugin(PluginArgs),
    /// Generate shell completion code.
    Completion { shell: Shell },
    /// Print the Lightrail version.
    Version,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Write configuration without interactive prompts.
    #[arg(long)]
    pub non_interactive: bool,

    /// Answers file used for non-interactive initialization.
    #[arg(long, value_name = "FILE")]
    pub from: Option<PathBuf>,

    /// Name of the first profile.
    #[arg(long, default_value = "preview")]
    pub profile: String,

    /// Replace an existing lightrail.toml after validation.
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
    Add { name: String },
    List,
    Show { name: String },
    Remove { name: String },
}

#[derive(Debug, Args)]
pub struct UpArgs {
    /// Print the plan without making changes.
    #[arg(long)]
    pub dry_run: bool,

    /// Preserve failed resources for debugging.
    #[arg(long)]
    pub keep_failed: bool,

    /// Maximum time to wait for the environment mutation lock.
    #[arg(long, default_value = "30s", value_parser = parse_duration)]
    pub lock_timeout: Duration,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Query every environment belonging to this project.
    #[arg(long)]
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
    /// Destroy every branch environment for this project.
    #[arg(long)]
    pub all: bool,

    /// Print the destruction plan without changing resources.
    #[arg(long)]
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
    Set {
        name: String,
        /// Read the value from stdin instead of an interactive prompt.
        #[arg(long)]
        stdin: bool,
    },
    List,
    Delete {
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
    Install { source: String },
    Sync,
    List,
    Inspect { id: String },
    Update { id: String },
    Remove { id: String },
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
            let start = std::env::current_dir()?;
            let summary = init::run(init::InitOptions {
                start,
                profile: arguments.profile,
                non_interactive: arguments.non_interactive || arguments.from.is_some(),
                answers_file: arguments.from,
                force: arguments.force,
            })
            .await?;
            match format {
                OutputFormat::Json => output::json(&summary),
                OutputFormat::Plain => output::line(summary.config_path.display()),
                OutputFormat::Human => {
                    output::line(format!(
                        "initialized `{}` at {}",
                        summary.project_slug,
                        summary.config_path.display()
                    ))?;
                    for app in summary.apps {
                        output::line(format!("  {:<16} {}:{}", app.name, app.service, app.port))?;
                    }
                    Ok(())
                }
            }
        }
        Command::Profile(arguments) => {
            let paths = ProjectPaths::discover(&std::env::current_dir()?)?;
            match arguments.command {
                ProfileCommand::Add { name } => {
                    let mutation =
                        profile::add(&paths.config, &name, selected_profile.as_deref()).await?;
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
                                    "{}{}  {:?}  target={}",
                                    item.name,
                                    if item.is_default { " (default)" } else { "" },
                                    item.isolation,
                                    item.target_plugin
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
                                "  isolation: {:?}\n  apps: {}",
                                selected.profile.isolation,
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
