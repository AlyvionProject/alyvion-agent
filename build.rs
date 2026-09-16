//! Компиляция контракта Agent <-> Core.
//!
//! Контракт НЕ дублируется в агенте: он лежит в отдельном репозитории
//! alyvion-shared, подключённом git-сабмодулем. Путь ОДИН и строго
//! фиксирован: external/alyvion-shared/proto/alyvion.proto.
//!

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protoc может отсутствовать в системе — используем вендорный бинарник.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // SAFETY: build-скрипт однопоточный, гонок за переменные окружения нет.
        unsafe { std::env::set_var("PROTOC", protoc) };
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir
        .join("external")
        .join("alyvion-shared")
        .join("proto");
    let proto_file = proto_dir.join("alyvion.proto");

    if !proto_file.exists() {
        return Err(format!(
            "не найден контракт: {}\n\
             Он лежит в репозитории alyvion-shared, подключённом сабмодулем.\n\
             Скорее всего сабмодуль не склонирован. Выполните в корне репозитория:\n\
             \n    python RUN_THIS.py\n\
             \n\
             Он склонирует сабмодуль и поставит нужную ревизию контракта.\n\
             Эквивалент вручную (ставит коммит ИЗ ИНДЕКСА репозитория):\n\
             \n    git submodule update --init --recursive",
            proto_file.display()
        )
        .into());
    }

    println!("cargo:rerun-if-changed={}", proto_file.display());

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&[proto_file], &[proto_dir])?;

    Ok(())
}
