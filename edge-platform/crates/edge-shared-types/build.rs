fn main() {
    let proto_root = std::path::PathBuf::from("../../proto");
    let platform_root = proto_root.join("edge/platform/v1");
    let release_proto = proto_root.join("edge/release/v1/release_set.proto");
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
    ]
    .into_iter()
    .map(|name| platform_root.join(name))
    .collect::<Vec<_>>();
    protos.push(release_proto);

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[proto_root])
        .expect("compile protobuf contracts");
}
