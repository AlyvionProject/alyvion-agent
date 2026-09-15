fn main() {
    tonic_build::compile_protos("proto/monitor.proto")
        .expect("не удалось скомпилировать proto");
}
