use lightrail_plugin_protocol::serve_stdio;
use lightrail_plugin_ssh::SshPlugin;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    serve_stdio(SshPlugin::new()).await?;
    Ok(())
}
