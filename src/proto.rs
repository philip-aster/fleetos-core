// Re-exports tonic gRPC modules generated from proto/v1/*.proto

pub mod identity {
    tonic::include_proto!("fleetos.v1.identity");
}

pub mod state {
    tonic::include_proto!("fleetos.v1.state");
}

pub mod secret {
    tonic::include_proto!("fleetos.v1.secret");
}
