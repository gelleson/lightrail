mod api;
mod model;
mod plugin;
mod ssh;

use lightrail_plugin_protocol::serve_stdio;
use plugin::HetznerPlugin;

#[tokio::main]
async fn main() {
    if let Err(error) = serve_stdio(HetznerPlugin::default()).await {
        eprintln!("lightrail Hetzner plugin transport failed: {error}");
        std::process::exit(1);
    }
}
