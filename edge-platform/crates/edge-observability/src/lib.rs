use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::Level;

const CORRELATION_ENV: &str = "EDGE_CORRELATION_ID";
const MAX_CORRELATION_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationContext {
    id: String,
}

impl CorrelationContext {
    pub fn id(&self) -> &str {
        &self.id
    }
}

pub fn init(component: &'static str) -> CorrelationContext {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_max_level(Level::INFO)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let id = env::var(CORRELATION_ENV)
        .ok()
        .filter(|value| valid_correlation_id(value))
        .unwrap_or_else(|| generated_correlation_id(component));

    tracing::info!(
        component,
        correlation_id = %id,
        event = "process.start",
        "process started"
    );

    CorrelationContext { id }
}

fn generated_correlation_id(component: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{component}-{}-{millis}", std::process::id())
}

fn valid_correlation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CORRELATION_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_id_accepts_only_bounded_safe_tokens() {
        assert!(valid_correlation_id("run-123:operation_4"));
        assert!(!valid_correlation_id(""));
        assert!(!valid_correlation_id("contains space"));
        assert!(!valid_correlation_id("secret=value"));
        assert!(!valid_correlation_id(&"x".repeat(MAX_CORRELATION_LEN + 1)));
    }

    #[test]
    fn generated_id_is_safe() {
        let value = generated_correlation_id("edge-controller");
        assert!(valid_correlation_id(&value));
        assert!(value.starts_with("edge-controller-"));
    }
}
