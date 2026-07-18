use lightrail_plugin_compose::ComposePlugin;

#[tokio::main]
async fn main() {
    if let Err(error) = lightrail_plugin_protocol::serve_stdio(ComposePlugin).await {
        eprintln!("compose plugin protocol failure: {error}");
        std::process::exit(1);
    }
}
