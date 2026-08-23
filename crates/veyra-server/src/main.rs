//! Standalone Veyra daemon entry point.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use veyra_server::{ApiState, RuntimeConfig, prepare_instance, serve};

#[derive(Debug, Parser)]
#[command(name = "veyra-server", version, about = "Local Veyra execution daemon")]
struct Arguments {
    /// Loopback address for the authenticated API.
    #[arg(long, default_value = "127.0.0.1:7843")]
    bind: SocketAddr,
    /// Durable database and local-key directory.
    #[arg(long, default_value = ".veyra-data")]
    data_directory: PathBuf,
    /// Capability-confined workspace root.
    #[arg(long, default_value = "workspace")]
    workspace: PathBuf,
    /// Stable workspace name used in resource scopes.
    #[arg(long, default_value = "default")]
    workspace_name: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("veyra=info")),
        )
        .with_target(false)
        .init();
    if let Err(error) = run(Arguments::parse()).await {
        eprintln!("veyra-server: {error}");
        std::process::exit(1);
    }
}

async fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = RuntimeConfig::new(arguments.data_directory, arguments.workspace);
    config.workspace_name = arguments.workspace_name;
    let instance = prepare_instance(&config)?;
    let listener = TcpListener::bind(arguments.bind).await?;
    let address = listener.local_addr()?;
    eprintln!("Veyra API listening at http://{address}/v1");
    eprintln!(
        "Local clients read authentication from {}",
        instance.token_path.display()
    );
    let state = ApiState::new(
        instance.kernel,
        Arc::clone(&instance.token),
        config.workspace_name,
    );
    serve(listener, state).await?;
    Ok(())
}
