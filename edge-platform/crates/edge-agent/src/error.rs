use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum AgentError {
    #[error("{0}")]
    Command(String),
    #[error(transparent)]
    Runtime(#[from] Box<dyn std::error::Error>),
}

impl AgentError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::Command(_) => "command",
            Self::Runtime(_) => "runtime",
        }
    }
}

impl From<String> for AgentError {
    fn from(value: String) -> Self {
        Self::Command(value)
    }
}

impl From<&str> for AgentError {
    fn from(value: &str) -> Self {
        Self::Command(value.to_owned())
    }
}
