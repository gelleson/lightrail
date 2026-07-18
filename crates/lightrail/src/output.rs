use std::io::{self, Write};

use clap::ValueEnum;
use serde::Serialize;

use crate::error::CliError;

/// Output format shared by machine-readable commands.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Plain,
}

pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    writeln!(lock)?;
    Ok(())
}

/// Write one compact JSON value followed by a newline.
pub fn json_line<T: Serialize + ?Sized>(value: &T) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value)?;
    writeln!(lock)?;
    Ok(())
}

pub fn line(value: impl std::fmt::Display) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    writeln!(lock, "{value}")?;
    Ok(())
}
