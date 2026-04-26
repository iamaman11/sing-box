use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;

use edge_shared_types::agent_service_server::{AgentService, AgentServiceServer};
use edge_shared_types::{AgentState, AgentVersion, Empty};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const DEFAULT_AGENT_ADDR: &str = "127.0.0.1:50061";

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
        "serve" => serve(agent_addr_from_args(2)?).await,
        other => Err(format!("unsupported command: {other}").into()),
    }
}

async fn serve(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    Server::builder()
        .add_service(AgentServiceServer::new(AgentServerImpl))
        .serve(addr)
        .await?;
    Ok(())
}

fn agent_addr_from_args(index: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr = env::args()
        .nth(index)
        .unwrap_or_else(|| DEFAULT_AGENT_ADDR.to_owned());
    Ok(addr.parse()?)
}

#[derive(Default)]
struct AgentServerImpl;

#[tonic::async_trait]
impl AgentService for AgentServerImpl {
    async fn get_health(&self, _request: Request<Empty>) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(agent_health_state()))
    }

    async fn get_readiness(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(agent_readiness_state()))
    }

    async fn get_runtime_state(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentState>, Status> {
        Ok(Response::new(agent_runtime_state()))
    }

    async fn get_version(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<AgentVersion>, Status> {
        Ok(Response::new(AgentVersion {
            name: "edge-agent".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }))
    }
}

fn agent_health_state() -> AgentState {
    AgentState {
        healthy: true,
        ..AgentState::bootstrap_placeholder()
    }
}

fn agent_readiness_state() -> AgentState {
    AgentState::bootstrap_placeholder()
}

fn agent_runtime_state() -> AgentState {
    AgentState::bootstrap_placeholder()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_shared_types::agent_service_server::AgentService;

    #[tokio::test]
    async fn returns_health_state() {
        let server = AgentServerImpl;
        let response = server.get_health(Request::new(Empty {})).await.unwrap();
        assert!(response.get_ref().healthy);
    }
}
