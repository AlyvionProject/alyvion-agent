#!/usr/bin/env python3
"""Клонирование и обновление общего контракта alyvion-shared.

ЭТОТ ФАЙЛ ЛОЖИТСЯ В КОРЕНЬ РЕПОЗИТОРИЯ И ОБСЛУЖИВАЕТ ТОЛЬКО ЕГО.

Скрипт определяет, в каком репозитории он лежит, и работает исключительно
с сабмодулем этого репозитория. Копии в `alyvion-core` и `alyvion-agent`
независимы: запуск в одном репозитории никогда не трогает соседний.
Поэтому файл продублирован в оба, и при изменении его нужно обновить
в обоих местах.

ЗАЧЕМ ЭТОТ СКРИПТ.

Контракт `alyvion.proto` лежит в отдельном репозитории `alyvion-shared`
и подключён как git-сабмодуль. Сабмодуль ссылается на КОНКРЕТНЫЙ КОММИТ,
а не на «последнюю версию файла», поэтому сам по себе он не обновляется:
пока кто-то не выполнит обновление вручную, репозиторий остаётся
на старой ревизии контракта.

Из-за этого возникают три неприятные ситуации, и все три лечит этот скрипт:

  1. САБМОДУЛЬ НЕ СКОПИРОВАН. Свежий клон содержит только `.gitmodules`
     и пустой каталог. Сборка падает, потому что `proto/alyvion.proto`
     физически отсутствует.

  2. САБМОДУЛЬ ПРИБИТ К СТАРОМУ КОММИТУ. Обычный
     `git submodule update --init` ставит ровно тот коммит, что записан
     в индексе родительского репозитория. Если это коммит, сделанный ДО
     появления контракта, то каталог создастся, а файла в нём не будет —
     и причина будет совершенно неочевидна.

  3. САБМОДУЛЬ ПОТЕРЯЛСЯ ИЗ ИНДЕКСА. Каталог на диске есть, а записи
     в индексе нет (например, закоммитили `.gitmodules` без gitlink).
     В этом состоянии `git submodule update --init` не работает вообще,
     с сообщением «did not match any file(s) known to git».

Скрипт приводит репозиторий к рабочему состоянию: при необходимости
клонирует сабмодуль, создаёт каталоги, восстанавливает запись в индексе
и переводит контракт на последний коммит ветки.

ЧЕГО СКРИПТ НЕ ДЕЛАЕТ. Он не создаёт коммитов и ничего не отправляет на
сервер. Обновление сабмодуля меняет только файлы на диске; чтобы закрепить
новую ревизию в истории, нужно закоммитить её отдельно — скрипт печатает
готовую команду.

ЗАПУСК (из корня того репозитория, где лежит файл):

    python RUN_THIS.py              # обновить контракт в этом репозитории
    python RUN_THIS.py --dry-run    # только показать, что будет сделано
    python RUN_THIS.py --check      # проверить состояние, ничего не меняя
    python RUN_THIS.py --branch dev # другая ветка контракта
    python RUN_THIS.py --url <URL>  # другой адрес репозитория контракта

Если SSH-ключ для GitHub не настроен, укажите HTTPS-адрес:

    python RUN_THIS.py --url https://github.com/AlyvionProject/alyvion-shared.git
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# --- Параметры по умолчанию -------------------------------------------------

SUBMODULE_PATH = "external/alyvion-shared"
PROTO_REL = "proto/alyvion.proto"
DEFAULT_BRANCH = "main"
DEFAULT_URL = "git@github.com:AlyvionProject/alyvion-shared.git"
HTTPS_URL = "https://github.com/AlyvionProject/alyvion-shared.git"


# --- Вывод ------------------------------------------------------------------

def _setup_stdout() -> None:
    """Русский текст в консоли Windows: без этого возможен UnicodeEncodeError."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def say(text: str = "") -> None:
    print(text)


def head(text: str) -> None:
    say()
    say(f"=== {text}")


# --- Запуск git -------------------------------------------------------------

class GitError(Exception):
    """Команда git завершилась с ошибкой."""


def _git_result(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def git(args: list[str], cwd: Path) -> str:
    """Выполняет git и возвращает stdout. При ошибке бросает GitError."""
    result = _git_result(args, cwd)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        raise GitError(f"git {' '.join(args)}: {message}")
    return result.stdout.strip()


def _rmtree(path: Path) -> None:
    """Удаляет каталог с содержимым.

    На Windows файлы в .git бывают доступны ТОЛЬКО ДЛЯ ЧТЕНИЯ, поэтому
    обычное удаление падает с PermissionError. Снимаем атрибут и повторяем.
    """

    def on_error(func, target, _exc):
        try:
            Path(target).chmod(0o700)
            func(target)
        except OSError:
            pass

    shutil.rmtree(path, onerror=on_error)


# --- Определение своего репозитория -----------------------------------------

def find_own_repo() -> Path | None:
    """Возвращает корень репозитория, в котором лежит этот файл.

    Именно так скрипт понимает, какой репозиторий обслуживать: свой, и
    только свой. Соседние репозитории проекта не затрагиваются.
    """
    here = Path(__file__).resolve().parent

    result = _git_result(["rev-parse", "--show-toplevel"], here)
    if result.returncode == 0 and result.stdout.strip():
        return Path(result.stdout.strip())

    # Запасной вариант: git недоступен, но каталог .git рядом есть.
    if (here / ".git").exists():
        return here
    return None


# --- Вспомогательные проверки ----------------------------------------------

def submodule_url(repo: Path) -> str | None:
    """Адрес сабмодуля из .gitmodules, если он там записан."""
    result = _git_result(
        ["config", "-f", ".gitmodules", "--get",
         f"submodule.{SUBMODULE_PATH}.url"],
        repo,
    )
    return result.stdout.strip() or None


def in_index(repo: Path) -> bool:
    """Есть ли запись сабмодуля в индексе (gitlink, режим 160000)."""
    result = _git_result(["ls-files", "-s", SUBMODULE_PATH], repo)
    return result.stdout.strip().startswith("160000")


def submodule_head(path: Path) -> str | None:
    """Текущий коммит сабмодуля, если он склонирован."""
    if not (path / ".git").exists():
        return None
    result = _git_result(["rev-parse", "HEAD"], path)
    return result.stdout.strip() or None


def short(sha: str | None) -> str:
    return sha[:7] if sha else "—"


def has_proto(path: Path) -> bool:
    return (path / PROTO_REL).is_file()


# --- Основная работа --------------------------------------------------------

def ensure_submodule(repo: Path, url: str, dry_run: bool) -> str:
    """Приводит сабмодуль к рабочему состоянию. Возвращает статус словами."""
    target = repo / SUBMODULE_PATH

    # Каталог external/ может отсутствовать в свежем клоне.
    if not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)

    if in_index(repo):
        # Запись есть — обычный путь: создать каталог, если нужно.
        if dry_run:
            return "запись в индексе есть, будет выполнено update --init"
        if not (target / ".git").exists():
            git(["submodule", "update", "--init", SUBMODULE_PATH], repo)
        return "обновлён"

    # Записи в индексе нет. Обычный `git submodule update --init` здесь
    # бесполезен — он падает с «did not match any file(s) known to git»,
    # поэтому регистрируем сабмодуль заново.
    #
    # Ключ -f нужен почти всегда, и вот почему. Даже если каталога на диске
    # нет, git может хранить служебный каталог сабмодуля в .git/modules/<путь>
    # — остаток от прежней регистрации. Без -f git отказывается работать:
    # «A git directory for ... is found locally». С -f он переиспользует
    # остаток, что нам и нужно.
    existed = (target / ".git").exists()
    if existed:
        reason = "каталог был, но запись в индексе потеряна"
    elif (repo / ".git" / "modules" / SUBMODULE_PATH).exists():
        reason = "остался служебный каталог в .git/modules"
    else:
        reason = "сабмодуль не склонирован"

    if dry_run:
        return f"будет зарегистрирован ({reason})"

    try:
        git(["submodule", "add", "-f", url, SUBMODULE_PATH], repo)
    except GitError as exc:
        text = str(exc)

        # Доступ — самая частая причина на чужой машине, и сообщение git
        # о ней невнятное.
        if "Permission denied" in text or "Could not read" in text:
            raise GitError(
                f"{text}\n"
                "  Похоже, нет доступа к репозиторию контракта.\n"
                "  Если SSH-ключ для GitHub не настроен, укажите HTTPS:\n"
                f"      python RUN_THIS.py --url {HTTPS_URL}"
            ) from exc

        # Запасной путь: служебный каталог остался от другой ревизии
        # и мешает переиспользованию. Убираем его и пробуем снова.
        stale = repo / ".git" / "modules" / SUBMODULE_PATH
        if stale.exists():
            say(f"  служебный каталог мешает, удаляю: {stale}")
            _rmtree(stale)
            git(["submodule", "add", "-f", url, SUBMODULE_PATH], repo)
        else:
            raise

    return f"зарегистрирован ({reason})"


def update_contract(repo: Path, branch: str, dry_run: bool) -> tuple[bool, str]:
    """Переводит контракт на последний коммит ветки.

    Возвращает (коммит изменился, пояснение).
    """
    target = repo / SUBMODULE_PATH

    if dry_run:
        return False, f"будет переведён на последний коммит ветки '{branch}'"

    before = submodule_head(target)

    # Именно fetch + checkout, а не `submodule update --init`: последний
    # поставил бы коммит, записанный в индексе родителя, а он может быть
    # сделан ДО появления контракта.
    try:
        git(["fetch", "--quiet", "origin", branch], target)
    except GitError as exc:
        raise GitError(
            f"{exc}\n"
            f"  Не удалось получить коммиты ветки '{branch}'.\n"
            "  Проверьте доступ к репозиторию контракта и имя ветки."
        ) from exc

    latest = git(["rev-parse", f"origin/{branch}"], target)
    if not latest:
        raise GitError(f"не удалось определить последний коммит ветки '{branch}'")

    if before == latest:
        return False, f"уже последняя версия ({short(latest)})"

    git(["checkout", "--quiet", latest], target)
    return True, f"{short(before)} -> {short(latest)}"


# --- Режим проверки ---------------------------------------------------------

def run_check(repo: Path) -> int:
    """Проверяет состояние, ничего не меняя. Возвращает код выхода."""
    target = repo / SUBMODULE_PATH
    sha = submodule_head(target)

    say(f"  сабмодуль : {'склонирован' if sha else 'НЕ склонирован'} ({short(sha)})")
    say(f"  контракт  : {PROTO_REL} — "
        f"{'есть' if has_proto(target) else 'ОТСУТСТВУЕТ'}")

    if in_index(repo):
        say("  индекс    : запись на месте")
    else:
        say("  индекс    : ЗАПИСИ НЕТ (нужно восстановить)")

    ok = bool(sha) and has_proto(target) and in_index(repo)

    head("Итог")
    if ok:
        say(f"  [OK] {repo.name}: сабмодуль на месте, контракт доступен.")
        return 0

    say(f"  [ПРОБЛЕМА] {repo.name}: контракт не готов к сборке.")
    say()
    say("Исправить (ничего не коммитит):")
    say("    python RUN_THIS.py")
    return 1


# --- Точка входа ------------------------------------------------------------

def main() -> int:
    _setup_stdout()

    parser = argparse.ArgumentParser(
        description="Клонирование и обновление контракта alyvion-shared "
                    "в ТЕКУЩЕМ репозитории.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  python RUN_THIS.py                 обновить контракт\n"
            "  python RUN_THIS.py --dry-run       показать план\n"
            "  python RUN_THIS.py --check         только проверить состояние\n"
            f"  python RUN_THIS.py --url {HTTPS_URL}\n"
            "                                     использовать HTTPS вместо SSH\n"
        ),
    )
    parser.add_argument("--branch", default=DEFAULT_BRANCH,
                        help=f"ветка контракта (по умолчанию {DEFAULT_BRANCH})")
    parser.add_argument("--url", default=None,
                        help="адрес репозитория контракта")
    parser.add_argument("--dry-run", action="store_true",
                        help="показать, что будет сделано, ничего не меняя")
    parser.add_argument("--check", action="store_true",
                        help="только проверить состояние (ничего не менять)")
    args = parser.parse_args()

    if args.dry_run and args.check:
        say("Ключи --dry-run и --check вместе не имеют смысла: "
            "--check уже ничего не меняет.")
        return 2

    repo = find_own_repo()
    if repo is None:
        say("ОШИБКА: не удалось определить репозиторий.")
        say("Положите RUN_THIS.py в корень репозитория (alyvion-core "
            "или alyvion-agent) и запустите снова.")
        return 1

    if args.check:
        say(f"Alyvion — проверка контракта alyvion-shared")
        say(f"  репозиторий : {repo.name}")
        head(repo.name)
        return run_check(repo)

    mode = "пробный запуск" if args.dry_run else "обновление контракта"

    say("Alyvion — общий контракт alyvion-shared")
    say(f"  репозиторий : {repo.name}  ({repo})")
    say(f"  режим       : {mode}")
    say(f"  ветка       : {args.branch}")

    # Адрес берём из .gitmodules, если он там записан: так скрипт продолжит
    # работать, если адрес репозитория когда-нибудь изменится.
    url = args.url or submodule_url(repo) or DEFAULT_URL
    say(f"  адрес       : {url}")

    target = repo / SUBMODULE_PATH
    before = submodule_head(target)

    head(repo.name)

    # 1. Убедиться, что сабмодуль склонирован и зарегистрирован.
    try:
        status = ensure_submodule(repo, url, args.dry_run)
    except GitError as exc:
        say(f"  ОШИБКА: {exc}")
        return 1
    say(f"  сабмодуль : {status}")

    # 2. Перевести на последний коммит ветки.
    try:
        changed, note = update_contract(repo, args.branch, args.dry_run)
    except GitError as exc:
        say(f"  ОШИБКА: {exc}")
        return 1
    say(f"  контракт  : {note}")

    # 3. Проверить, что файл контракта действительно на месте. Это главная
    #    проверка: сабмодуль может быть «успешно обновлён» на коммит, где
    #    контракта ещё нет.
    if args.dry_run:
        say(f"  проверка  : {PROTO_REL} (будет проверен после обновления)")
        head("Итог")
        say("  Это пробный запуск — изменения не вносились.")
        say("  Выполнить по-настоящему:  python RUN_THIS.py")
        return 0

    if not has_proto(target):
        say(f"  ОШИБКА: после обновления отсутствует {PROTO_REL}")
        say()
        say("  В ветке нет коммита с контрактом. Проверьте ветку:")
        say(f"      python RUN_THIS.py --check --branch <ветка>")
        return 1

    say(f"  проверка  : {PROTO_REL} на месте")

    # --- Итог ---------------------------------------------------------------
    head("Итог")
    say(f"  [OK] {repo.name}: контракт готов к сборке.")

    after = submodule_head(target)
    if not (changed or before != after):
        say()
        say("Контракт уже был на последней версии — менять нечего.")
        return 0

    # --- Что делать дальше --------------------------------------------------
    say()
    say("Что дальше.")
    say("  1. Закрепить новую ревизию контракта в истории (скрипт этого")
    say("     намеренно не делает — иначе коммит появился бы незаметно):")
    say(f"         git -C {repo.name} add {SUBMODULE_PATH} .gitmodules")
    say(f"         git -C {repo.name} commit -m \"обновлён контракт alyvion-shared\"")
    say()
    say("  2. Смена контракта не ловится компилятором на стороне Python:")
    say("     стабы нужно перегенерировать, иначе прототип останется")
    say("     на старой версии протокола.")
    say("         cd alyvion-core && .venv/bin/python scripts/gen_proto.py")
    say()
    say("  3. Пересобрать агент: Rust-агент (cargo build).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say()
        say("Прервано пользователем.")
        sys.exit(130)
