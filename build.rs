fn main() {
    tonic_build::configure()
        .build_server(true)
        .compile(
            &["proto/zkp-auth.proto"],
            &["proto/"]  // Specify the root location to search for proto dependencies
        )
        .unwrap();
}
