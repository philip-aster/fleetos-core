// build.rs
// Compiles Protobuf definitions in proto/v1/ into Rust code during `cargo build`

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true) // Generate gRPC server traits
        .build_client(true) // Generate gRPC client structs
        .compile_protos(
            &[
                "proto/v1/identity.proto",
                "proto/v1/state.proto",
                "proto/v1/secret.proto",
            ],
            &["proto/v1"], // Search path for imported proto files
        )?;
    println!("cargo:rerun-if-changed=proto/v1/identity.proto");
    println!("cargo:rerun-if-changed=proto/v1/state.proto");
    Ok(())
}
