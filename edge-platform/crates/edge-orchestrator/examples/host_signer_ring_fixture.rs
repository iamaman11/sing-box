// Ephemeral TEST key ONLY. No production key access, stdout or artifact.
// GitHub CI passes a protected runner-temp path and removes it on exit.
use base64::Engine as _;
use ring::signature::KeyPair;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("output path required")?;
    let rng = ring::rand::SystemRandom::new();
    let bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(bytes.as_ref())?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes.as_ref());
    let pubkey = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref());
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = options.open(path)?;
    write!(out, "{{\"ring_pkcs8_v2\":\"{encoded}\",\"public_key\":\"{pubkey}\"}}")?;
    out.sync_all()?;
    println!("host_signer_ring_test_fixture=CREATED_PRIVATE_EPHEMERAL");
    Ok(())
}
