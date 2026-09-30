fn main() {
    connectrpc_build::Config::new()
        .descriptor_set("../../proto/aster/application/v1alpha1/aster.fds.bin")
        .files(&["aster/application/v1alpha1/aster.proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("generate the pinned Aster ConnectRPC API");
}
