//! Veyra desktop entry point and embedded loopback API lifecycle.

use serde::Serialize;
use tauri::{Manager, State};
use tokio::net::TcpListener;
use veyra_server::{ApiState, RuntimeConfig, prepare_instance, serve};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionInfo {
    api_url: String,
    token: String,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri command extractors are framework-owned values.
fn connection_info(connection: State<'_, ConnectionInfo>) -> ConnectionInfo {
    connection.inner().clone()
}

fn main() {
    tauri::Builder::default()
        .setup(|application| {
            let data_directory = application.path().app_local_data_dir()?.join("runtime");
            let workspace = application.path().app_local_data_dir()?.join("workspace");
            let config = RuntimeConfig::new(data_directory, workspace);
            let instance = prepare_instance(&config)?;
            let listener = tauri::async_runtime::block_on(TcpListener::bind("127.0.0.1:0"))?;
            let address = listener.local_addr()?;
            let state = ApiState::new(
                instance.kernel,
                instance.token.clone(),
                config.workspace_name,
            );
            application.manage(ConnectionInfo {
                api_url: format!("http://{address}/v1/"),
                token: instance.token.to_string(),
            });
            tauri::async_runtime::spawn(async move {
                if let Err(error) = serve(listener, state).await {
                    eprintln!("embedded Veyra API stopped: {error}");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![connection_info])
        .run(tauri::generate_context!())
        .expect("failed to run Veyra desktop application");
}
