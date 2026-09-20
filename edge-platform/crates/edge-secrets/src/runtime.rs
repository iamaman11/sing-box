use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use x25519_dalek::{PublicKey, StaticSecret};

pub const APPLICATION_RUNTIME_SECRET_KEYS: &[&str] = &[
    "PROXY_PASSWORD",
    "VLESS_UUID",
    "HY2_PASSWORD",
    "REALITY_PRIVATE_KEY",
    "REALITY_PUBLIC_KEY",
    "REALITY_SHORT_ID",
    "VLESS_WARP_UUID",
    "HY2_WARP_PASSWORD",
    "REALITY_WARP_PRIVATE_KEY",
    "REALITY_WARP_PUBLIC_KEY",
    "REALITY_WARP_SHORT_ID",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationRuntimeSecrets {
    pub proxy_password: String,
    pub vless_uuid: String,
    pub hy2_password: String,
    pub reality_private_key: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub vless_warp_uuid: String,
    pub hy2_warp_password: String,
    pub reality_warp_private_key: String,
    pub reality_warp_public_key: String,
    pub reality_warp_short_id: String,
}

impl ApplicationRuntimeSecrets {
    pub fn generate() -> Self {
        let (reality_private_key, reality_public_key) = generate_reality_pair();
        let (reality_warp_private_key, reality_warp_public_key) = generate_reality_pair();
        Self {
            proxy_password: random_hex(32),
            vless_uuid: generate_uuid_v4(),
            hy2_password: random_hex(32),
            reality_private_key,
            reality_public_key,
            reality_short_id: random_hex(8),
            vless_warp_uuid: generate_uuid_v4(),
            hy2_warp_password: random_hex(32),
            reality_warp_private_key,
            reality_warp_public_key,
            reality_warp_short_id: random_hex(8),
        }
    }

    pub fn parse_env(raw: &str) -> Result<Self, String> {
        let values = parse_closed_env(raw)?;
        let result = Self {
            proxy_password: required(&values, "PROXY_PASSWORD")?,
            vless_uuid: required(&values, "VLESS_UUID")?,
            hy2_password: required(&values, "HY2_PASSWORD")?,
            reality_private_key: required(&values, "REALITY_PRIVATE_KEY")?,
            reality_public_key: required(&values, "REALITY_PUBLIC_KEY")?,
            reality_short_id: required(&values, "REALITY_SHORT_ID")?,
            vless_warp_uuid: required(&values, "VLESS_WARP_UUID")?,
            hy2_warp_password: required(&values, "HY2_WARP_PASSWORD")?,
            reality_warp_private_key: required(&values, "REALITY_WARP_PRIVATE_KEY")?,
            reality_warp_public_key: required(&values, "REALITY_WARP_PUBLIC_KEY")?,
            reality_warp_short_id: required(&values, "REALITY_WARP_SHORT_ID")?,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn render_env(&self) -> String {
        [
            ("PROXY_PASSWORD", self.proxy_password.as_str()),
            ("VLESS_UUID", self.vless_uuid.as_str()),
            ("HY2_PASSWORD", self.hy2_password.as_str()),
            ("REALITY_PRIVATE_KEY", self.reality_private_key.as_str()),
            ("REALITY_PUBLIC_KEY", self.reality_public_key.as_str()),
            ("REALITY_SHORT_ID", self.reality_short_id.as_str()),
            ("VLESS_WARP_UUID", self.vless_warp_uuid.as_str()),
            ("HY2_WARP_PASSWORD", self.hy2_warp_password.as_str()),
            ("REALITY_WARP_PRIVATE_KEY", self.reality_warp_private_key.as_str()),
            ("REALITY_WARP_PUBLIC_KEY", self.reality_warp_public_key.as_str()),
            ("REALITY_WARP_SHORT_ID", self.reality_warp_short_id.as_str()),
        ]
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_hex("PROXY_PASSWORD", &self.proxy_password, 64)?;
        validate_uuid("VLESS_UUID", &self.vless_uuid)?;
        validate_hex("HY2_PASSWORD", &self.hy2_password, 64)?;
        validate_key("REALITY_PRIVATE_KEY", &self.reality_private_key)?;
        validate_key("REALITY_PUBLIC_KEY", &self.reality_public_key)?;
        validate_hex("REALITY_SHORT_ID", &self.reality_short_id, 16)?;
        validate_uuid("VLESS_WARP_UUID", &self.vless_warp_uuid)?;
        validate_hex("HY2_WARP_PASSWORD", &self.hy2_warp_password, 64)?;
        validate_key("REALITY_WARP_PRIVATE_KEY", &self.reality_warp_private_key)?;
        validate_key("REALITY_WARP_PUBLIC_KEY", &self.reality_warp_public_key)?;
        validate_hex("REALITY_WARP_SHORT_ID", &self.reality_warp_short_id, 16)
    }
}

fn parse_closed_env(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let expected = APPLICATION_RUNTIME_SECRET_KEYS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut values = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("secret line {} must use KEY=VALUE syntax", index + 1))?;
        if !expected.contains(key) {
            return Err(format!("unexpected secret key: {key}"));
        }
        if value.is_empty() {
            return Err(format!("secret {key} must be non-empty"));
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("secret key is duplicated: {key}"));
        }
    }
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        let missing = expected.difference(&observed).copied().collect::<Vec<_>>();
        return Err(format!("secret store is missing keys: {}", missing.join(",")));
    }
    Ok(values)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| format!("secret store is missing {key}"))
}

fn generate_reality_pair() -> (String, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (
        URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.to_bytes()),
    )
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buffer);
    buffer.into_iter().map(|byte| format!("{byte:02x}")).collect()
}

fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

fn validate_hex(label: &str, value: &str, expected_len: usize) -> Result<(), String> {
    if value.len() != expected_len
        || !value.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(format!("{label} must be exactly {expected_len} lowercase hexadecimal characters"));
    }
    Ok(())
}

fn validate_uuid(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 36
        || !value.chars().enumerate().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
    {
        return Err(format!("{label} must be a lowercase UUID"));
    }
    Ok(())
}

fn validate_key(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!("{label} must be a 43-character unpadded base64url X25519 key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_round_trip() {
        let generated = ApplicationRuntimeSecrets::generate();
        generated.validate().unwrap();
        let parsed = ApplicationRuntimeSecrets::parse_env(&generated.render_env()).unwrap();
        assert_eq!(parsed, generated);
    }

    #[test]
    fn rejects_unknown_or_missing_keys() {
        let generated = ApplicationRuntimeSecrets::generate();
        let mut unknown = generated.render_env();
        unknown.push_str("UNKNOWN=value\n");
        assert!(ApplicationRuntimeSecrets::parse_env(&unknown).is_err());

        let missing = generated
            .render_env()
            .lines()
            .filter(|line| !line.starts_with("PROXY_PASSWORD="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(ApplicationRuntimeSecrets::parse_env(&missing).is_err());
    }
}
