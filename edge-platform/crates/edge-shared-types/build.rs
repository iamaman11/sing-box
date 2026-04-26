fn main() {
    let proto_root = std::path::PathBuf::from("../../proto");
    let proto_file = proto_root.join("edge_platform.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");

    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto_file], &[proto_root])
        .expect("compile protobuf contracts");
}
