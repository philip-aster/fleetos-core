// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = PathBuf::from("proto");

    // Collect all proto files
    let protos = [
        proto_dir.join("identity.proto"),
        proto_dir.join("state.proto"),
        proto_dir.join("secret.proto"),
        proto_dir.join("provisioning.proto"),
        proto_dir.join("admin.proto"),
        proto_dir.join("workload.proto"),
    ];

    // Tell Cargo to rerun this build script if any proto file changes
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    // Use tonic_prost_build (not tonic_build) to configure and compile
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &[proto_dir])?;

    Ok(())
}
