use edge_shared_types::{
    CONFIG_SCHEMA_VERSION, CloudflareRuntime, DB_SCHEMA_VERSION, OciImage,
    RELEASE_SET_SCHEMA_VERSION, ReleaseSet, SchemaVersions, SingBoxRelease, VmRuntime,
    WindowsRuntime, decode_release_set, encode_release_set, release_set_sha256,
};
use ring::digest::{Context, SHA256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const CREATE_FLAGS: &[&str] = &[
    "output",
    "sha256-output",
    "source-revision",
    "sing-box-version",
    "windows-sing-box-sha256",
    "linux-sing-box-sha256",
    "windows-artifact-sha256",
    "windows-controller-sha256",
    "windows-console-sha256",
    "edge-agent-sha256",
    "edge-controller-sha256",
    "sing-box-image",
    "warp-egress-image",
    "docker-engine-version",
    "containerd-version",
    "compose-version",
    "warp-version",
    "mesh-image",
];

const VERIFY_FLAGS: &[&str] = &[
    "input",
    "sha256-file",
    "source-revision",
    "windows-artifact",
    "windows-controller",
    "windows-console",
    "windows-sing-box",
    "linux-sing-box",
    "edge-agent",
    "edge-controller",
];

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let flags = parse_flags(args.collect())?;

    match command.as_str() {
        "create" => create_release_set(&flags),
        "verify" => verify_release_set(&flags),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: edge-release-set create|verify --flag value ...".to_owned()
}

fn parse_flags(args: Vec<String>) -> Result<BTreeMap<String, String>, String> {
    if args.len() % 2 != 0 {
        return Err("flags must be provided as --name value pairs".to_owned());
    }

    let mut flags = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let name = pair[0]
            .strip_prefix("--")
            .ok_or_else(|| format!("expected flag name beginning with --, got {}", pair[0]))?;
        if name.is_empty() {
            return Err("empty flag name is not allowed".to_owned());
        }
        if flags.insert(name.to_owned(), pair[1].clone()).is_some() {
            return Err(format!("duplicate --{name}"));
        }
    }
    Ok(flags)
}

fn require_allowed(flags: &BTreeMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    for name in flags.keys() {
        if !allowed.contains(&name.as_str()) {
            return Err(format!("unsupported --{name}"));
        }
    }
    for name in allowed {
        if !flags.contains_key(*name) {
            return Err(format!("missing required --{name}"));
        }
    }
    Ok(())
}

fn flag<'a>(flags: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required --{name}"))
}

fn create_release_set(flags: &BTreeMap<String, String>) -> Result<(), String> {
    require_allowed(flags, CREATE_FLAGS)?;

    let windows_sing_box = digest_from_hex(
        "windows-sing-box-sha256",
        flag(flags, "windows-sing-box-sha256")?,
    )?;
    let release = ReleaseSet {
        schema_version: RELEASE_SET_SCHEMA_VERSION,
        source_revision: flag(flags, "source-revision")?.to_owned(),
        sing_box: Some(SingBoxRelease {
            version: flag(flags, "sing-box-version")?.to_owned(),
            windows_amd64_sha256: windows_sing_box.clone(),
            linux_amd64_sha256: digest_from_hex(
                "linux-sing-box-sha256",
                flag(flags, "linux-sing-box-sha256")?,
            )?,
        }),
        windows_runtime: Some(WindowsRuntime {
            artifact_sha256: digest_from_hex(
                "windows-artifact-sha256",
                flag(flags, "windows-artifact-sha256")?,
            )?,
            controller_sha256: digest_from_hex(
                "windows-controller-sha256",
                flag(flags, "windows-controller-sha256")?,
            )?,
            console_sha256: digest_from_hex(
                "windows-console-sha256",
                flag(flags, "windows-console-sha256")?,
            )?,
            sing_box_sha256: windows_sing_box,
        }),
        vm_runtime: Some(VmRuntime {
            edge_agent_sha256: digest_from_hex(
                "edge-agent-sha256",
                flag(flags, "edge-agent-sha256")?,
            )?,
            edge_controller_sha256: digest_from_hex(
                "edge-controller-sha256",
                flag(flags, "edge-controller-sha256")?,
            )?,
            sing_box_image: Some(parse_image_ref(
                "sing-box-image",
                flag(flags, "sing-box-image")?,
            )?),
            warp_egress_image: Some(parse_image_ref(
                "warp-egress-image",
                flag(flags, "warp-egress-image")?,
            )?),
            docker_engine_version: flag(flags, "docker-engine-version")?.to_owned(),
            containerd_version: flag(flags, "containerd-version")?.to_owned(),
            compose_version: flag(flags, "compose-version")?.to_owned(),
        }),
        cloudflare: Some(CloudflareRuntime {
            warp_version: flag(flags, "warp-version")?.to_owned(),
            mesh_image: Some(parse_image_ref("mesh-image", flag(flags, "mesh-image")?)?),
        }),
        schemas: Some(SchemaVersions {
            config_schema: CONFIG_SCHEMA_VERSION,
            db_schema: DB_SCHEMA_VERSION,
        }),
    };

    let bytes = encode_release_set(&release)?;
    let digest = release_set_sha256(&bytes)?;
    let output = PathBuf::from(flag(flags, "output")?);
    let sha256_output = PathBuf::from(flag(flags, "sha256-output")?);
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "release-set output must have a UTF-8 filename".to_owned())?;

    fs::write(&output, &bytes)
        .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    fs::write(
        &sha256_output,
        format!("{digest}  {file_name}\n").as_bytes(),
    )
    .map_err(|error| {
        format!(
            "failed to write release-set SHA-256 file {}: {error}",
            sha256_output.display()
        )
    })?;

    println!("release_set_sha256={digest}");
    Ok(())
}

fn verify_release_set(flags: &BTreeMap<String, String>) -> Result<(), String> {
    require_allowed(flags, VERIFY_FLAGS)?;

    let input = PathBuf::from(flag(flags, "input")?);
    let sha256_file = PathBuf::from(flag(flags, "sha256-file")?);
    let bytes =
        fs::read(&input).map_err(|error| format!("failed to read {}: {error}", input.display()))?;
    let release = decode_release_set(&bytes)?;
    let digest = release_set_sha256(&bytes)?;

    if release.source_revision != flag(flags, "source-revision")? {
        return Err(format!(
            "release-set source revision mismatch: expected {}, got {}",
            flag(flags, "source-revision")?,
            release.source_revision
        ));
    }

    let file_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "release-set input must have a UTF-8 filename".to_owned())?;
    let expected_sha_file = format!("{digest}  {file_name}\n");
    let actual_sha_file = fs::read_to_string(&sha256_file).map_err(|error| {
        format!(
            "failed to read release-set SHA-256 file {}: {error}",
            sha256_file.display()
        )
    })?;
    if actual_sha_file != expected_sha_file {
        return Err("release-set SHA-256 sidecar does not match exact protobuf bytes".to_owned());
    }

    let sing_box = release
        .sing_box
        .as_ref()
        .ok_or_else(|| "release-set sing_box is required".to_owned())?;
    let windows = release
        .windows_runtime
        .as_ref()
        .ok_or_else(|| "release-set windows_runtime is required".to_owned())?;
    let vm = release
        .vm_runtime
        .as_ref()
        .ok_or_else(|| "release-set vm_runtime is required".to_owned())?;
    let cloudflare = release
        .cloudflare
        .as_ref()
        .ok_or_else(|| "release-set cloudflare is required".to_owned())?;

    verify_file_digest(
        "windows artifact",
        Path::new(flag(flags, "windows-artifact")?),
        &windows.artifact_sha256,
    )?;
    verify_file_digest(
        "Windows controller",
        Path::new(flag(flags, "windows-controller")?),
        &windows.controller_sha256,
    )?;
    verify_file_digest(
        "Windows console",
        Path::new(flag(flags, "windows-console")?),
        &windows.console_sha256,
    )?;
    verify_file_digest(
        "Windows sing-box",
        Path::new(flag(flags, "windows-sing-box")?),
        &windows.sing_box_sha256,
    )?;
    verify_file_digest(
        "Linux sing-box",
        Path::new(flag(flags, "linux-sing-box")?),
        &sing_box.linux_amd64_sha256,
    )?;
    verify_file_digest(
        "edge-agent",
        Path::new(flag(flags, "edge-agent")?),
        &vm.edge_agent_sha256,
    )?;
    if release.schema_version >= 2 {
        verify_file_digest(
            "edge-controller",
            Path::new(flag(flags, "edge-controller")?),
            &vm.edge_controller_sha256,
        )?;
    }

    println!("release_set_sha256={digest}");
    println!("schema_version={}", release.schema_version);
    println!("source_revision={}", release.source_revision);
    println!(
        "edge_agent_sha256={}",
        digest_to_hex(&vm.edge_agent_sha256)
    );
    if release.schema_version >= 2 {
        println!(
            "edge_controller_sha256={}",
            digest_to_hex(&vm.edge_controller_sha256)
        );
    }
    println!(
        "sing_box_image={}",
        image_ref(
            vm.sing_box_image
                .as_ref()
                .ok_or_else(|| "vm_runtime.sing_box_image is required".to_owned())?
        )
    );
    println!(
        "warp_egress_image={}",
        image_ref(
            vm.warp_egress_image
                .as_ref()
                .ok_or_else(|| "vm_runtime.warp_egress_image is required".to_owned())?
        )
    );
    println!(
        "mesh_image={}",
        image_ref(
            cloudflare
                .mesh_image
                .as_ref()
                .ok_or_else(|| "cloudflare.mesh_image is required".to_owned())?
        )
    );
    Ok(())
}

fn digest_from_hex(label: &str, value: &str) -> Result<Vec<u8>, String> {
    if value.len() != 64
        || !value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(format!(
            "{label} must be exactly 64 lowercase hexadecimal characters"
        ));
    }

    (0..64)
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|error| format!("invalid {label}: {error}"))
        })
        .collect()
}

fn digest_to_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_image_ref(label: &str, value: &str) -> Result<OciImage, String> {
    let (repository, digest) = value
        .split_once("@sha256:")
        .ok_or_else(|| format!("{label} must be repository@sha256:<64hex>"))?;
    if repository.is_empty() || repository.contains('@') {
        return Err(format!("{label} contains an invalid OCI repository"));
    }
    Ok(OciImage {
        repository: repository.to_owned(),
        sha256: digest_from_hex(label, digest)?,
    })
}

fn image_ref(image: &OciImage) -> String {
    format!(
        "{}@sha256:{}",
        image.repository,
        digest_to_hex(&image.sha256)
    )
}

fn verify_file_digest(label: &str, path: &Path, expected: &[u8]) -> Result<(), String> {
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(format!(
            "{label} SHA-256 mismatch for {}: expected {}, got {}",
            path.display(),
            digest_to_hex(expected),
            digest_to_hex(&actual)
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context.finish().as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_parser_rejects_uppercase_and_wrong_length() {
        assert!(digest_from_hex("test", &"a".repeat(64)).is_ok());
        assert!(digest_from_hex("test", &"A".repeat(64)).is_err());
        assert!(digest_from_hex("test", &"a".repeat(63)).is_err());
    }

    #[test]
    fn image_ref_round_trips_exact_digest() {
        let value = format!("ghcr.io/iamaman11/example@sha256:{}", "b".repeat(64));
        let image = parse_image_ref("image", &value).unwrap();
        assert_eq!(image_ref(&image), value);
    }

    #[test]
    fn duplicate_flags_fail_closed() {
        let error = parse_flags(vec![
            "--input".to_owned(),
            "a".to_owned(),
            "--input".to_owned(),
            "b".to_owned(),
        ])
        .unwrap_err();
        assert!(error.contains("duplicate"));
    }
}
