#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

//! Lightrail's user-facing CLI and provider-independent orchestration shell.

pub mod admin;
pub mod cli;
pub mod commands;
pub mod compose;
pub mod doctor;
pub mod error;
pub mod journal;
pub mod orchestrator;
pub mod output;
pub mod plugin_host;
pub mod plugin_registry;
pub mod process;
pub mod project;
pub mod secrets;
pub mod telemetry;
pub mod workspace;

use cli::Cli;
use error::CliError;

/// Dispatch a parsed CLI request.
///
/// Command implementations are added incrementally behind this stable entry point.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    cli::dispatch(cli).await
}
