fn main() {
    let proto_root = std::path::PathBuf::from("../../proto");
    let platform_proto = proto_root.join("edge_platform.proto");
    let release_proto = proto_root.join("release_set.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    println!("cargo:rerun-if-changed={}", platform_proto.display());
    println!("cargo:rerun-if-changed={}", release_proto.display());

    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[platform_proto, release_proto], &[proto_root])
        .expect("compile protobuf contracts");
}
