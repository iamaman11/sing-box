mod runtime;
pub use runtime::{APPLICATION_RUNTIME_SECRET_KEYS, ApplicationRuntimeSecrets};

use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretReference {
    Env(String),
    File(PathBuf),
    Path(PathBuf),
}

pub fn default_env_ref(name: &str) -> String {
    format!("env:{name}")
}

pub fn parse_secret_reference(raw: &str) -> Result<SecretReference, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("secret reference is empty".to_owned());
    }

    if let Some(value) = trimmed.strip_prefix("env:") {
        let name = value.trim();
        if name.is_empty() {
            return Err("env secret reference requires a variable name".to_owned());
        }
        return Ok(SecretReference::Env(name.to_owned()));
    }
    if let Some(value) = trimmed.strip_prefix("file:") {
        let path = value.trim();
        if path.is_empty() {
            return Err("file secret reference requires a path".to_owned());
        }
        return Ok(SecretReference::File(PathBuf::from(path)));
    }
    if let Some(value) = trimmed.strip_prefix("path:") {
        let path = value.trim();
        if path.is_empty() {
            return Err("path secret reference requires a path".to_owned());
        }
        return Ok(SecretReference::Path(PathBuf::from(path)));
    }
    Err(format!("unsupported secret reference: {trimmed}"))
}

pub fn resolve_secret_text(reference: &str) -> Result<String, String> {
    match parse_secret_reference(reference)? {
        SecretReference::Env(name) => env::var(&name)
            .map_err(|_| format!("environment variable is not set: {name}"))
            .and_then(normalize_secret_text),
        SecretReference::File(path) => fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))
            .and_then(normalize_secret_text),
        SecretReference::Path(path) => Err(format!(
            "path secret reference cannot be resolved as text: {}",
            path.display()
        )),
    }
}

pub fn resolve_secret_path(reference: &str) -> Result<PathBuf, String> {
    match parse_secret_reference(reference)? {
        SecretReference::Env(name) => {
            let value =
                env::var(&name).map_err(|_| format!("environment variable is not set: {name}"))?;
            normalize_secret_path(PathBuf::from(value))
        }
        SecretReference::File(path) | SecretReference::Path(path) => normalize_secret_path(path),
    }
}

fn normalize_secret_text(value: String) -> Result<String, String> {
    let trimmed = value.trim().to_owned();
    if trimmed.is_empty() {
        return Err("resolved secret value is empty".to_owned());
    }
    Ok(trimmed)
}

fn normalize_secret_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("resolved secret path is empty".to_owned());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_supported_secret_references() {
        assert_eq!(
            parse_secret_reference("env:VULTR_API_KEY").unwrap(),
            SecretReference::Env("VULTR_API_KEY".to_owned())
        );
        assert_eq!(
            parse_secret_reference("file:/tmp/token.txt").unwrap(),
            SecretReference::File(PathBuf::from("/tmp/token.txt"))
        );
        assert_eq!(
            parse_secret_reference("path:/tmp/id_rsa").unwrap(),
            SecretReference::Path(PathBuf::from("/tmp/id_rsa"))
        );
    }

    #[test]
    fn resolves_file_text() {
        let path = temp_path("edge-secret");
        fs::write(&path, " token-from-file \n").unwrap();
        assert_eq!(
            resolve_secret_text(&format!("file:{}", path.display())).unwrap(),
            "token-from-file"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_literal_secret_references() {
        assert!(parse_secret_reference("literal:secret").is_err());
        assert!(resolve_secret_text("literal:secret").is_err());
    }

    #[test]
    fn resolves_path_reference() {
        let path = temp_path("edge-secret-path");
        assert_eq!(
            resolve_secret_path(&format!("path:{}", path.display())).unwrap(),
            path
        );
    }

    fn temp_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{label}-{unique}"))
    }
}
