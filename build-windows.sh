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

# Конфигурацию для Windows готовим отдельно от Linux-версии: в исходном
# файле реагирование включено, а на Windows оно невыполнимо. Оставить
# allow_response_actions = true значило бы объявить Core возможности,
# которых на узле нет, — оператор получал бы ошибки вместо результата.
# Источники событий тоже выключаем: на Windows их нет, и включать их
# означало бы только лишние попытки чтения несуществующих путей.
CONFIG_OUT="$DIST/alyvion-agent.toml"

sed -e 's/^allow_response_actions *= *true/allow_response_actions = false/' \
    -e 's/^journald *= *true/journald = false/' \
    -e 's/^auth_log *= *true/auth_log = false/' \
    -e 's/^auditd *= *true/auditd = false/' \
    "$AGENT_ROOT/alyvion-agent.toml" > "$CONFIG_OUT.tmp"

cat > "$CONFIG_OUT.head" <<'CFGHEAD'
# Конфигурация агента Alyvion для Windows.
# Подготовлена сборкой build-windows.sh.
#
# Отличия от Linux-версии и их причина:
#   * allow_response_actions = false — реагирование на Windows пока не
#     реализовано (нужны Stop-Process, netsh, блокировка учётных записей);
#   * journald, auth_log, auditd = false — этих источников событий
#     на Windows не существует.
#
# Что работает: телеметрия узла, связь с Core, проверка канала.
#
# ОБЯЗАТЕЛЬНО ПОПРАВЬТЕ ПЕРЕД ЗАПУСКОМ:
#   core_url — адрес Core, доступный С ЭТОЙ машины. Значение по умолчанию
#   http://127.0.0.1:5050 годится, только если Core работает на этом же
#   узле. Для отдельного сервера укажите его адрес, например
#   core_url = "http://192.168.1.10:5050".
#   Порт 5050 — это порт приёма данных (gRPC), а НЕ веб-интерфейс (5080).
#   Если Core за межсетевым экраном, откройте на нём порт 5050.

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

ЧТО БУДЕТ РАБОТАТЬ НА WINDOWS, А ЧТО НЕТ
  Работает:
    * телеметрия узла (ЦП, память, диски, сеть, процессы) — через sysinfo;
    * связь с Core по gRPC, регистрация,Heartbeat;
    * действие проверки канала (PingAction).
  НЕ работает (код рассчитан на Linux):
    * сбор событий: journald, /var/log/secure, /var/log/auth.log,
      /var/log/audit/audit.log — на Windows этих источников нет;
    * реагирование: iptables (блокировка адресов), kill/usermod
      (завершение процессов, блокировка учётных записей).
  Подсистемы не откажут и не уронят агент: они просто не найдут
  источников и вернут пустой результат. Но событий ИБ и реального
  реагирования на Windows не будет — их нужно реализовывать отдельно
  (журнал событий Windows, Sysmon, WMI, Stop-Process и т. п.).

  По этой причине НЕ включайте allow_response_actions = true для
  агента под Windows: он объявит возможности, которые не сможет
  выполнить, и оператор будет получать ошибки вместо результата.
MSG
