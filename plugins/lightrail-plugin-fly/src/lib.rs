//! Agentless Fly.io Apps and Machines executable plugin.
//!
//! Provider mutation stays behind the Fly HTTP API boundary. Local builds use
//! Docker Buildx with private, operation-scoped registry authentication.

mod api;
mod command;
mod model;
mod plugin;

pub use plugin::{FlyPlugin, PLUGIN_ID};
