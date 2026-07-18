use tracing_subscriber::EnvFilter;

/// Initialize local diagnostics. Lightrail does not emit product telemetry.
pub fn init(verbose: u8) {
    let fallback = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(verbose > 1)
        .with_writer(std::io::stderr)
        .try_init();
}
