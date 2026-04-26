use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use edge_controller_core::collect_controller_status;
use edge_shared_types::controller_service_client::ControllerServiceClient;
use edge_shared_types::controller_service_server::{ControllerService, ControllerServiceServer};
use edge_shared_types::{ControllerStatus, Empty, PlatformError};
use edge_state::EdgeState;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

const DEFAULT_CONTROLLER_ADDR: &str = "127.0.0.1:50051";
const DEFAULT_STATE_DB: &str = "edge-platform/.runtime/controller-state.sqlite";

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = env::args().nth(1).unwrap_or_else(|| "serve".to_owned());

    match command.as_str() {
        "serve" => {
            let repo_root = repo_root_from_args(2)?;
            let addr = controller_addr_from_args(3)?;
            serve(repo_root, addr).await
        }
        "get-status" => {
            let endpoint = controller_endpoint_from_args(2);
            let status = fetch_status(endpoint).await?;
            io::stdout().write_all(&status.encode_proto())?;
            Ok(())
        }
        other => Err(format!("unsupported command: {other}").into()),
    }
}

async fn serve(repo_root: PathBuf, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = repo_root.join(DEFAULT_STATE_DB);
    let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path)?));
    let service = ControllerServerImpl { repo_root, state };

    Server::builder()
        .add_service(ControllerServiceServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

async fn fetch_status(endpoint: String) -> Result<ControllerStatus, Box<dyn std::error::Error>> {
    let mut client = ControllerServiceClient::<Channel>::connect(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
    Ok(response.into_inner())
}

fn controller_addr_from_args(index: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr = env::args()
        .nth(index)
        .unwrap_or_else(|| DEFAULT_CONTROLLER_ADDR.to_owned());
    Ok(addr.parse()?)
}

fn controller_endpoint_from_args(index: usize) -> String {
    env::args()
        .nth(index)
        .unwrap_or_else(|| format!("http://{DEFAULT_CONTROLLER_ADDR}"))
}

fn repo_root_from_args(index: usize) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = env::args().nth(index) {
        return Ok(PathBuf::from(path));
    }

    let cwd = env::current_dir()?;
    if looks_like_repo_root(&cwd) {
        return Ok(cwd);
    }

    if let Some(parent) = cwd.parent()
        && looks_like_repo_root(parent)
    {
        return Ok(parent.to_path_buf());
    }

    Ok(cwd)
}

fn looks_like_repo_root(path: &Path) -> bool {
    path.join("RUST-ULTIMATE-PLATFORM-PLAN.md").exists()
}

struct ControllerServerImpl {
    repo_root: PathBuf,
    state: Arc<Mutex<EdgeState>>,
}

#[tonic::async_trait]
impl ControllerService for ControllerServerImpl {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<ControllerStatus>, Status> {
        let status =
            collect_controller_status(&self.repo_root).map_err(platform_error_to_status)?;

        self.state
            .lock()
            .map_err(|_| Status::internal("controller state mutex poisoned"))?
            .store_local_observation("controller_status", &status.encode_proto())
            .map_err(|err| Status::internal(format!("failed to store status snapshot: {err}")))?;

        Ok(Response::new(status))
    }
}

fn platform_error_to_status(err: PlatformError) -> Status {
    Status::internal(format!("{} [{}]: {}", err.code, err.stage, err.message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_repo_root_from_workspace() {
        let repo_root = repo_root_from_args(usize::MAX).unwrap();
        assert!(repo_root.exists());
    }

    #[tokio::test]
    async fn collects_status_through_service_impl() {
        let repo_root = PathBuf::from("/home/bose/projects/sing-box");
        let db_path = repo_root.join("edge-platform/.runtime/test-controller-state.sqlite");
        let state = Arc::new(Mutex::new(EdgeState::open_or_create(&db_path).unwrap()));
        let service = ControllerServerImpl { repo_root, state };

        let response = service.get_status(Request::new(Empty {})).await.unwrap();
        assert!(response.get_ref().inventory.is_some());
        let _ = std::fs::remove_file(db_path);
    }
}
