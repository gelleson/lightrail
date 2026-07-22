use lightrail_plugin_fly::FlyPlugin;
use lightrail_plugin_protocol::serve_stdio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve_stdio(FlyPlugin::default()).await?;
    Ok(())
}
