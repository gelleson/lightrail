use clap::Parser;
use lightrail::cli::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    lightrail::telemetry::init(cli.verbose);

    if let Err(error) = lightrail::run(cli).await {
        eprintln!("error: {error}");
        std::process::exit(error.exit_code());
    }
}
