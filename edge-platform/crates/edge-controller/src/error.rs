use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ControllerError {
    #[error("{0}")]
    Command(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Runtime(#[from] Box<dyn std::error::Error>),
}

impl ControllerError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::Command(_) => "command",
            Self::Io(_) => "io",
            Self::Runtime(_) => "runtime",
        }
    }
}

impl From<String> for ControllerError {
    fn from(value: String) -> Self {
        Self::Command(value)
    }
}

impl From<&str> for ControllerError {
    fn from(value: &str) -> Self {
        Self::Command(value.to_owned())
    }
}
