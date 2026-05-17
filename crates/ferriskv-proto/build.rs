use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("workspace root not found")?;
    let proto_dir = workspace_root.join("proto");
    let proto_file = proto_dir.join("ferriskv.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());

    let fds = protox::compile([proto_file], [proto_dir])?;

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .bytes(["."])
        .compile_fds(fds)?;

    Ok(())
}
