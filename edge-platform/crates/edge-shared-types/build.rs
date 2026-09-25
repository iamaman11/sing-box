use std::io::Write;
use std::process::{Command, Stdio};

fn main() {
    let proto_root = std::path::PathBuf::from("../../proto");
    let platform_root = proto_root.join("edge/platform/v1");
    let release_proto = proto_root.join("edge/release/v1/release_set.proto");
    let production_proto = platform_root.join("production.proto");
    let production_textproto =
        std::path::PathBuf::from("../../../infra/production/production.textproto");

    let mut protos = [
        "common.proto",
        "error.proto",
        "operation.proto",
        "lifecycle.proto",
        "runtime.proto",
        "bundle.proto",
        "secrets.proto",
        "diagnostics.proto",
        "controller.proto",
        "orchestrator.proto",
        "agent.proto",
        "production.proto",
    ]
    .into_iter()
    .map(|name| platform_root.join(name))
    .collect::<Vec<_>>();
    protos.push(release_proto);

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        production_textproto.display()
    );

    unsafe {
        std::env::set_var("PROTOC", &protoc);
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[proto_root.clone()])
        .expect("compile protobuf contracts");

    let desired_text =
        std::fs::read(&production_textproto).expect("read canonical production textproto");
    let mut child = Command::new(&protoc)
        .arg(format!("--proto_path={}", proto_root.display()))
        .arg("--encode=edge.platform.v1.ProductionDesiredState")
        .arg(&production_proto)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start protoc production textproto encoder");

    child
        .stdin
        .take()
        .expect("protoc stdin")
        .write_all(&desired_text)
        .expect("write production textproto to protoc");

    let output = child
        .wait_with_output()
        .expect("wait for production textproto encoder");
    if !output.status.success() {
        panic!(
            "canonical production textproto is invalid: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("production-desired-state.pb"), output.stdout)
        .expect("write canonical production protobuf");
}
