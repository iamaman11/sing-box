use clap::{Args, Parser, Subcommand};
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "edge-agent", version, about = "Bounded edge host agent")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    pub fn command_name(&self) -> &'static str {
        self.command.as_ref().map(Command::name).unwrap_or("serve")
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Serve(ServeArgs),
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Serve(_) => "serve",
        }
    }
}

#[derive(Debug, Args, Default)]
pub(crate) struct ServeArgs {
    pub addr: Option<SocketAddr>,
    pub stack_dir: Option<PathBuf>,
}

impl ServeArgs {
    pub fn resolve(self) -> Result<(SocketAddr, PathBuf), String> {
        let addr = match self.addr {
            Some(addr) => addr,
            None => env::var("EDGE_AGENT_ADDR")
                .unwrap_or_else(|_| crate::DEFAULT_AGENT_ADDR.to_owned())
                .parse()
                .map_err(|err| format!("invalid EDGE_AGENT_ADDR: {err}"))?,
        };
        let stack_dir = self
            .stack_dir
            .or_else(|| env::var("EDGE_STACK_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(crate::DEFAULT_STACK_DIR));
        Ok((addr, stack_dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn agent_cli_is_closed() {
        assert!(Cli::try_parse_from(["edge-agent", "serve"]).is_ok());
        assert!(Cli::try_parse_from(["edge-agent", "exec", "whoami"]).is_err());
    }
}
