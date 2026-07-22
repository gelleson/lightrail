use lightrail_plugin_kubernetes::KubernetesPlugin;
use lightrail_plugin_protocol::serve_stdio;

#[tokio::main]
async fn main() {
    if let Err(error) = serve_stdio(KubernetesPlugin::default()).await {
        eprintln!("lightrail Kubernetes plugin transport failed: {error}");
        std::process::exit(1);
    }
}
