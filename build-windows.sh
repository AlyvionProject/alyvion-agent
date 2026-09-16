#!/usr/bin/env bash
# =============================================================================
#  Alyvion — сборка агента под Windows (64 бита) из Linux.
#
#  Использование:
#      cd alyvion-agent
#      ./build-windows.sh
#
#  Результат:
#      dist/alyvion-agent.exe        — готовый исполняемый файл
#      dist/alyvion-agent.toml       — конфигурация рядом с ним
#
#  Про окружение. На этом стенде домашний каталог смонтирован ТОЛЬКО ДЛЯ
#  ЧТЕНИЯ, поэтому rustup и инструменты кросс-сборки вынесены в каталог
#  проекта (.toolchain). На обычной машине нужен лишь rustup с таргетом
#  x86_64-pc-windows-gnu и mingw-w64 — скрипт это учитывает: если
#  инструменты уже есть в системе, он ими и воспользуется.
# =============================================================================

set -euo pipefail

AGENT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$AGENT_ROOT/.." && pwd)"
TOOLCHAIN="$PROJECT_ROOT/.toolchain"

TARGET="x86_64-pc-windows-gnu"
DIST="$AGENT_ROOT/dist"

# --- 0. Окружение проекта ----------------------------------------------------
# ВАЖНО: env.sh задаёт CARGO_HOME. Без него cargo смотрит в $HOME/.cargo,
# а на этом стенде домашний каталог доступен только для чтения — сборка
# падала бы с «failed to download» даже при полном кэше пакетов.
if [ -f "$PROJECT_ROOT/alyvion-core/scripts/env.sh" ]; then
    # shellcheck disable=SC1091
    . "$PROJECT_ROOT/alyvion-core/scripts/env.sh"
fi

# --- 1. Инструменты кросс-сборки --------------------------------------------
# Приоритет у инструментов проекта: они нужны на стенде с read-only /home.
if [ -d "$TOOLCHAIN/rustup" ]; then
    export RUSTUP_HOME="$TOOLCHAIN/rustup"
    echo "== rustup взят из проекта: $RUSTUP_HOME"
fi

MINGW_BIN=""
if [ -x "$TOOLCHAIN/mingw-rpm/root/usr/bin/x86_64-w64-mingw32-gcc" ]; then
    MINGW_BIN="$TOOLCHAIN/mingw-rpm/root/usr/bin"
    echo "== mingw взят из проекта: $MINGW_BIN"
elif command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    MINGW_BIN="$(dirname "$(command -v x86_64-w64-mingw32-gcc)")"
    echo "== mingw взят из системы: $MINGW_BIN"
else
    cat >&2 <<'MSG'
ОШИБКА: не найден компилятор mingw-w64 (x86_64-w64-mingw32-gcc).

Он нужен, потому что Rust для связи с Windows использует линкер mingw.
Установка:
    Fedora:  sudo dnf install mingw64-gcc
    Debian:  sudo apt install gcc-mingw-w64-x86-64
    Arch:    sudo pacman -S mingw-w64-gcc
MSG
    exit 1
fi

# Подключаем каталоги инструментов к пути поиска.
export PATH="$MINGW_BIN:$PATH"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$MINGW_BIN/x86_64-w64-mingw32-gcc"

# --- 2. Настройки сборки -----------------------------------------------------
# env.sh включает офлайн-режим: на этом стенде сеть до crates.io нестабильна,
# и для Linux-зависимостей кэш уже полон. Но зависимости Windows (ntapi,
# windows-sys и прочие) в кэш попадают только при первой кросс-сборке,
# поэтому здесь офлайн-режим снимается. Он остаётся включённым, если
# переменная уже задана снаружи — так повторные сборки идут без сети:
#     CARGO_NET_OFFLINE=true ./build-windows.sh
if [ -z "${CARGO_NET_OFFLINE:-}" ] || [ "${ALYVION_WINDOWS_OFFLINE:-}" != "1" ]; then
    export CARGO_NET_OFFLINE=false
fi

cd "$AGENT_ROOT"

echo "== цель сборки: $TARGET"

# --- 3. Стандартная библиотека Windows --------------------------------------
if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "== устанавливаю стандартную библиотеку для $TARGET"
    rustup target add "$TARGET"
fi

# --- 4. Сборка ---------------------------------------------------------------
echo "== собираю (release)"
cargo build --target "$TARGET" --release

# --- 5. Раскладка готового комплекта ----------------------------------------
BIN="$AGENT_ROOT/target/$TARGET/release/alyvion-agent.exe"
if [ ! -f "$BIN" ]; then
    echo "ОШИБКА: сборка завершилась, но файл не найден: $BIN" >&2
    exit 1
fi

mkdir -p "$DIST"
cp -f "$BIN" "$DIST/alyvion-agent.exe"

# Конфигурацию для Windows готовим отдельно от Linux-версии: сборщики
# и реагирование у платформ разные, поэтому один файл на обе не годится.
#
# Агент умеет определять платформу и выбирать умолчания сам
# (CollectorToggles::for_current_platform), но конфигурация рядом
# с исполняемым файлом задаёт значения ЯВНО — так администратор видит,
# что именно включено, и не зависит от того, какая сборка запущена.
CONFIG_OUT="$DIST/alyvion-agent.toml"

# Источники Linux на Windows не существуют: их опрос давал бы только
# попытки чтения отсутствующих путей.
sed -e 's/^journald *= *true/journald = false/' \
    -e 's/^auth_log *= *true/auth_log = false/' \
    -e 's/^auditd *= *true/auditd = false/' \
    -e 's/^winevent *= *false/winevent = true/' \
    "$AGENT_ROOT/alyvion-agent.toml" > "$CONFIG_OUT.tmp"

cat > "$CONFIG_OUT.head" <<'CFGHEAD'
# Конфигурация агента Alyvion для Windows.
# Подготовлена сборкой build-windows.sh.
#
# Отличия от Linux-версии:
#   * journald, auth_log, auditd = false — этих источников событий
#     в Windows не существует;
#   * winevent = true — сбор журнала событий Windows (Security, System,
#     Application, PowerShell).
#
# ЧТО РАБОТАЕТ:
#   * телеметрия узла (процессы, память, диск, сеть);
#   * сбор журнала событий Windows: входы в систему, создание процессов,
#     изменение учётных записей, установка служб, очистка журнала;
#   * реагирование: блокировка адреса, завершение процесса, отключение
#     учётной записи, сетевая изоляция, карантин файла, сбор сведений.
#
# ПРАВА. Для чтения канала Security нужны права администратора либо
# членство учётной записи агента в группе «Читатели журнала событий»
# (Event Log Readers). Без них каналы System, Application и PowerShell
# читаются, а события входа в систему — нет: агент сообщит об этом
# в своём журнале, гадать не придётся.
#
# РЕАГИРОВАНИЕ ВКЛЮЧЕНО. allow_response_actions = true означает, что
# агент будет менять систему по команде оператора: блокировать адреса
# через netsh, завершать процессы через taskkill, отключать учётные
# записи через net user. Если это нежелательно, поставьте false —
# Core перестанет показывать кнопки действий для этого узла.
#
# ОБЯЗАТЕЛЬНО ПОПРАВЬТЕ ПЕРЕД ЗАПУСКОМ:
#   core_url — адрес Core, доступный С ЭТОЙ машины. Значение по умолчанию
#   http://127.0.0.1:5050 годится, только если Core работает на этом же
#   узле. Для отдельного сервера укажите его адрес, например
#   core_url = "http://192.168.1.10:5050".
#   Порт 5050 — это порт приёма данных (gRPC), а НЕ веб-интерфейс (5080).
#   Если Core за межсетевым экраном, откройте на нём порт 5050.
#
# SYSMON. sysmon = false, потому что Sysmon — отдельный продукт,
# устанавливаемый самостоятельно. Если он установлен, поставьте true,
# и агент начнёт читать его канал.

CFGHEAD

cat "$CONFIG_OUT.head" "$CONFIG_OUT.tmp" > "$CONFIG_OUT"
rm -f "$CONFIG_OUT.head" "$CONFIG_OUT.tmp"

echo
echo "============================================================="
echo " Готово."
echo "   Исполняемый файл : $DIST/alyvion-agent.exe"
echo "   Конфигурация     : $DIST/alyvion-agent.toml"
echo "   Размер           : $(du -h "$DIST/alyvion-agent.exe" | cut -f1)"
echo "============================================================="
cat <<'MSG'

ЧТО РАБОТАЕТ НА WINDOWS
  * телеметрия узла (ЦП, память, диски, сеть, процессы) — через sysinfo;
  * связь с Core по gRPC, регистрация, Heartbeat;
  * СБОР ЖУРНАЛА СОБЫТИЙ: каналы Security, System, Application,
    PowerShell 5.1 и PowerShell 7. События: входы в систему, создание
    процессов, повышение прав, изменение учётных записей и групп,
    установка служб, очистка журнала;
  * РЕАГИРОВАНИЕ: блокировка адреса и снятие блокировки, завершение
    процесса, отключение и включение учётной записи, сетевая изоляция
    и её снятие, карантин файла, сбор сведений об узле.

ПРАВА НА ЧТЕНИЕ ЖУРНАЛА
  Канал Security защищён. Для него нужны права администратора либо
  членство учётной записи агента в группе «Читатели журнала событий»
  (Event Log Readers). Без них каналы System, Application и PowerShell
  читаются, а события входа в систему — нет. Агент сообщит об этом
  в своём журнале с указанием причины.

SYSMON
  В конфигурации sysmon = false: Sysmon — отдельный продукт, который
  надо устанавливать самостоятельно. Если он установлен, поставьте true.

ОГРАНИЧЕНИЯ РЕАГИРОВАНИЯ
  * Сетевая изоляция блокирует только НОВЫЕ входящие соединения:
    канал с Core сохраняется, поэтому узел остаётся управляемым.
  * Карантин системных каталогов (C:\Windows, C:\Program Files)
    запрещён: ошибка оператора не должна ломать узел.
  * Встроенная учётная запись администратора не отключается.
MSG
