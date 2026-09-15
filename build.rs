//! Компиляция контракта Agent <-> Core.
//!
//! Proto-файл НЕ дублируется в агенте: берётся общий из репозитория
//! (`proto/alyvion.proto`) — тот же самый, что компилирует Core.
//! Это гарантирует, что обе стороны всегда говорят на одном языке.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protoc может отсутствовать в системе — используем вендорный бинарник.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build-скрипт однопоточный, гонок за переменные окружения нет.
        unsafe { std::env::set_var("PROTOC", protoc) };
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let repo_root = manifest_dir
        .parent()
        .ok_or("не удалось определить корень репозитория")?;

    let proto_dir = repo_root.join("proto");
    let proto_file = proto_dir.join("alyvion.proto");

    if !proto_file.exists() {
        return Err(format!("не найден общий proto-файл: {}", proto_file.display()).into());
    }

    println!("cargo:rerun-if-changed={}", proto_file.display());

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[proto_file], &[proto_dir])?;

    Ok(())
}
