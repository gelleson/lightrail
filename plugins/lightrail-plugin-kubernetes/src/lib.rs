//! Agentless deployment to an existing Kubernetes cluster.
//!
//! The plugin always addresses an explicitly configured kube context. It
//! builds the current local checkout with Buildx, pushes deterministic OCI
//! image tags, renders ordinary Kubernetes resources, and applies them through
//! `kubectl`. It never creates, resizes, or deletes a cluster or node.

mod command;
mod config;
mod lock;
mod model;
mod plugin;

pub use config::Settings;
pub use plugin::KubernetesPlugin;

/// Stable executable-plugin identifier.
pub const PLUGIN_ID: &str = "dev.lightrail.kubernetes";
