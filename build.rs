fn main() {
    tonic_build::configure()
        .build_server(true)
        // .out_dir("src/")
        .compile(
            &["proto/zkp-auth.proto"],
            &["proto/"]  // Specify the root location to search for proto dependencies
        )
        .unwrap();
}
