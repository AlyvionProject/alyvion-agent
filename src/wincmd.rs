//! Формирование команд Windows и разбор их результатов.
//!
//! ПОЧЕМУ ЭТОТ МОДУЛЬ НЕ ЗАВИСИТ ОТ WINDOWS. Здесь только СОСТАВЛЕНИЕ
//! команд (какая программа и с какими аргументами) и разбор их исхода.
//! Само выполнение требует Windows и живёт в `sysops.rs`. Разделение
//! сделано ради проверяемости: правильность командной строки — самая
//! ошибкоопасная часть (перепутанный ключ `netsh` не даёт ошибки, а тихо
//! не блокирует адрес), и её нужно уметь проверять тестами на сборочной
//! машине, не имея Windows под рукой.
//!
//! ПОЧЕМУ УСПЕХ ОПРЕДЕЛЯЕТСЯ ПО КОДУ ВОЗВРАТА. Вывод утилит Windows
//! локализован: на русской системе `netsh` напишет «ОК.», на английской —
//! «Ok.». Разбор текста сломался бы при смене языка, поэтому решение
//! принимается по коду возврата (0 — успех), который от языка не зависит,
//! а текст используется только для сообщения оператору.

/// Описание запускаемой программы: имя и список аргументов.
///
/// Аргументы — именно СПИСОК, а не одна строка: агент запускает программу
/// без промежуточной оболочки, поэтому спецсимволы в аргументах
/// не интерпретируются. Это защищает от подстановки команд.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandSpec {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// Командная строка для журнала агента.
    ///
    /// Нужна для разбора инцидентов: администратор должен видеть, что
    /// именно выполнил агент. Значения с пробелами заключаются в кавычки,
    /// чтобы запись в журнале читалась однозначно.
    pub fn display(&self) -> String {
        let mut parts = vec![self.program.clone()];
        for arg in &self.args {
            if arg.contains(' ') {
                parts.push(format!("\"{arg}\""));
            } else {
                parts.push(arg.clone());
            }
        }
        parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
//  Сетевые действия
// ---------------------------------------------------------------------------

/// Имя правила брандмауэра для конкретного адреса.
///
/// ПОЧЕМУ АДРЕС В ИМЕНИ ПРАВИЛА. Снятие блокировки должно находить ровно
/// то правило, которое поставил агент. Если бы имя было общим, снятие
/// блокировки одного адреса удалило бы правило другого, а перебор всех
/// правил брандмауэра — это лишние запросы и риск задеть чужое правило.
/// Детерминированное имя делает операцию точной и обратимой.
pub fn block_rule_name(ip: &str) -> String {
    format!("Alyvion block {ip}")
}

/// Имя правила сетевой изоляции.
pub const ISOLATE_RULE_NAME: &str = "Alyvion isolate inbound";

/// Блокировка входящих соединений с указанного адреса.
///
/// Направление `dir=in`: блокируется входящий трафик от адреса.
/// Исходящие соединения узла не затрагиваются — иначе узел потерял бы
/// связь с Core и стал бы неуправляемым.
pub fn block_ip(ip: &str) -> CommandSpec {
    CommandSpec::new(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", block_rule_name(ip)),
            "dir=in",
            "action=block",
            &format!("remoteip={ip}"),
        ],
    )
}

/// Снятие блокировки адреса.
pub fn unblock_ip(ip: &str) -> CommandSpec {
    CommandSpec::new(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", block_rule_name(ip)),
        ],
    )
}

/// Изоляция узла: запрет НОВЫХ входящих соединений.
///
/// ВАЖНО про безопасность самой операции. Брандмауэр Windows хранит
/// состояние соединений, поэтому блокировка входящих не разрывает уже
/// установленные соединения и не мешает узлу самому обращаться наружу.
/// Канал с Core инициативен со стороны агента, поэтому он сохраняется,
/// а узел остаётся управляемым. Полная изоляция в прототипе
/// не применяется — она лишила бы оператора возможности снять её.
pub fn isolate_host() -> CommandSpec {
    CommandSpec::new(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={ISOLATE_RULE_NAME}"),
            "dir=in",
            "action=block",
            "protocol=any",
        ],
    )
}

/// Снятие изоляции узла.
pub fn release_host() -> CommandSpec {
    CommandSpec::new(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={ISOLATE_RULE_NAME}"),
        ],
    )
}

// ---------------------------------------------------------------------------
//  Действия над процессами
// ---------------------------------------------------------------------------

/// Завершение процесса по идентификатору.
///
/// Ключ `/F` означает принудительное завершение. Мягкого аналога SIGTERM
/// в Windows нет: `taskkill` без `/F` посылает сообщение о закрытии только
/// процессам с оконным интерфейсом, а службы и консольные процессы его
/// игнорируют. Поэтому используется принудительное завершение —
/// это ожидаемое поведение для реагирования на инцидент.
///
/// Ключ `/T` (завершить дерево процессов) НЕ используется сознательно:
/// он завершил бы и дочерние процессы, которые могли не иметь отношения
/// к инциденту.
pub fn kill_process(pid: u32) -> CommandSpec {
    CommandSpec::new("taskkill", &["/PID", &pid.to_string(), "/F"])
}

/// Проверка существования процесса по идентификатору.
///
/// `tasklist /FI "PID eq N" /NH` выводит строку процесса либо сообщение
/// об отсутствии. Наличие проверяется по коду возврата и содержимому.
pub fn process_query(pid: u32) -> CommandSpec {
    CommandSpec::new(
        "tasklist",
        &["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"],
    )
}

/// Снимок списка процессов.
pub fn list_processes() -> CommandSpec {
    CommandSpec::new("tasklist", &["/FO", "CSV", "/NH"])
}

// ---------------------------------------------------------------------------
//  Действия над учётными записями
// ---------------------------------------------------------------------------

/// Включение или отключение локальной учётной записи.
///
/// Используется `net user`, а не командлет PowerShell `Disable-LocalUser`:
/// `net user` есть в любой версии Windows и не требует среды PowerShell,
/// запуск которой заметно медленнее и зависит от политики выполнения
/// сценариев (`ExecutionPolicy`), которая на узле может быть запрещена.
pub fn set_user_enabled(user: &str, enabled: bool) -> CommandSpec {
    CommandSpec::new(
        "net",
        &[
            "user",
            user,
            if enabled { "/active:yes" } else { "/active:no" },
        ],
    )
}

/// Проверка состояния учётной записи.
pub fn query_user(user: &str) -> CommandSpec {
    CommandSpec::new("net", &["user", user])
}

// ---------------------------------------------------------------------------
//  Сбор информации об узле (форензика)
// ---------------------------------------------------------------------------

/// Установленные сетевые соединения с идентификаторами процессов.
pub fn list_connections() -> CommandSpec {
    CommandSpec::new("netstat", &["-ano"])
}

/// Сведения о системе.
pub fn system_info() -> CommandSpec {
    CommandSpec::new("systeminfo", &[])
}

// ---------------------------------------------------------------------------
//  Карантин файлов
// ---------------------------------------------------------------------------

/// Каталог карантина под Windows.
pub const QUARANTINE_DIR: &str = r"C:\ProgramData\Alyvion\quarantine";

/// Системные пути, карантин которых запрещён.
///
/// ПОЧЕМУ ЗАПРЕТ НУЖЕН. Оператор может ошибиться в пути. Перемещение
/// файла из системного каталога способно нарушить работу узла, поэтому
/// такие пути отклоняются агентом независимо от прав оператора.
const FORBIDDEN_PREFIXES: [&str; 8] = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
    r"\\?\",
    r"\\.\",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
];

/// Проверяет, запрещён ли карантин указанного пути.
///
/// Возвращает причину отказа либо `None`, если путь допустим.
///
/// Сравнение БЕЗ учёта регистра: файловая система Windows регистр
/// не различает, поэтому `c:\windows\...` и `C:\Windows\...` — один
/// и тот же путь, и проверка «в лоб» пропустила бы вторую запись.
pub fn forbidden_quarantine_reason(path: &str) -> Option<String> {
    let normalized = path.trim().replace('/', r"\");

    for prefix in FORBIDDEN_PREFIXES {
        if normalized
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
        {
            return Some(format!(
                "карантин системного пути {path} запрещён: он относится к {prefix}"
            ));
        }
    }

    None
}

/// Проверяет, что путь вообще похож на абсолютный путь Windows.
///
/// Относительный путь в команде реагирования означал бы перемещение файла
/// из рабочего каталога агента, а не то, что имел в виду оператор.
pub fn is_absolute_windows_path(path: &str) -> bool {
    let trimmed = path.trim();

    // Вид `C:\...` или `\\server\share\...`.
    let bytes: Vec<char> = trimmed.chars().collect();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == ':'
        && (bytes[2] == '\\' || bytes[2] == '/')
    {
        return true;
    }

    trimmed.starts_with(r"\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn блокировка_адреса_ставит_правило_на_входящие() {
        let spec = block_ip("192.168.1.50");

        assert_eq!(spec.program, "netsh");
        assert_eq!(
            spec.args,
            vec![
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Alyvion block 192.168.1.50",
                "dir=in",
                "action=block",
                "remoteip=192.168.1.50",
            ]
        );
    }

    #[test]
    fn снятие_блокировки_удаляет_ровно_то_же_правило() {
        let added = block_ip("10.0.0.7");
        let removed = unblock_ip("10.0.0.7");

        // Имя правила в обеих командах обязано совпасть, иначе снятие
        // блокировки не найдёт правило агента.
        let added_name = added
            .args
            .iter()
            .find(|a| a.starts_with("name="))
            .expect("имя правила должно быть указано");
        let removed_name = removed
            .args
            .iter()
            .find(|a| a.starts_with("name="))
            .expect("имя правила должно быть указано");

        assert_eq!(added_name, removed_name);
        assert!(removed.args.contains(&"delete".to_string()));
    }

    #[test]
    fn блокировка_не_трогает_исходящие_соединения() {
        // Направление dir=in, а не dir=out: иначе узел потерял бы
        // возможность обращаться к Core и стал бы неуправляемым.
        let spec = block_ip("1.2.3.4");
        assert!(spec.args.contains(&"dir=in".to_string()));
        assert!(!spec.args.contains(&"dir=out".to_string()));
    }

    #[test]
    fn адреса_в_правилах_не_пересекаются() {
        assert_ne!(block_rule_name("1.2.3.4"), block_rule_name("1.2.3.5"));
    }

    #[test]
    fn изоляция_и_снятие_используют_одно_имя_правила() {
        let add = isolate_host();
        let remove = release_host();

        assert!(add.args.contains(&format!("name={ISOLATE_RULE_NAME}")));
        assert!(remove.args.contains(&format!("name={ISOLATE_RULE_NAME}")));
        assert!(remove.args.contains(&"delete".to_string()));
    }

    #[test]
    fn завершение_процесса_принудительное_и_по_pid() {
        let spec = kill_process(4200);

        assert_eq!(spec.program, "taskkill");
        assert_eq!(spec.args, vec!["/PID", "4200", "/F"]);
        // Дерево процессов не завершаем: /T затронул бы чужие процессы.
        assert!(!spec.args.contains(&"/T".to_string()));
    }

    #[test]
    fn отключение_учётной_записи_ставит_active_no() {
        let spec = set_user_enabled("operator", false);
        assert_eq!(spec.program, "net");
        assert_eq!(spec.args, vec!["user", "operator", "/active:no"]);
    }

    #[test]
    fn включение_учётной_записи_ставит_active_yes() {
        let spec = set_user_enabled("operator", true);
        assert_eq!(spec.args, vec!["user", "operator", "/active:yes"]);
    }

    #[test]
    fn запрещён_карантин_системных_каталогов() {
        assert!(forbidden_quarantine_reason(r"C:\Windows\System32\kernel32.dll").is_some());
        assert!(forbidden_quarantine_reason(r"C:\Program Files\app\a.exe").is_some());
        assert!(forbidden_quarantine_reason(r"C:\Program Files (x86)\app\a.exe").is_some());
    }

    #[test]
    fn запрет_не_зависит_от_регистра_и_разделителей() {
        // Файловая система Windows регистр не различает, поэтому
        // проверка обязана его игнорировать.
        assert!(forbidden_quarantine_reason(r"c:\windows\system32\a.dll").is_some());
        assert!(forbidden_quarantine_reason(r"C:\WINDOWS\a.dll").is_some());
        assert!(forbidden_quarantine_reason("C:/Windows/a.dll").is_some());
    }

    #[test]
    fn пользовательский_путь_карантину_разрешён() {
        assert!(forbidden_quarantine_reason(r"C:\Users\operator\Downloads\bad.exe").is_none());
        assert!(forbidden_quarantine_reason(r"D:\temp\suspicious.exe").is_none());
    }

    #[test]
    fn распознаётся_абсолютный_путь_windows() {
        assert!(is_absolute_windows_path(r"C:\Users\a\b.exe"));
        assert!(is_absolute_windows_path("D:/data/b.exe"));
        assert!(is_absolute_windows_path(r"\\server\share\file.exe"));

        assert!(!is_absolute_windows_path("b.exe"));
        assert!(!is_absolute_windows_path(r"..\..\windows\x.dll"));
        assert!(!is_absolute_windows_path(""));
    }

    #[test]
    fn командная_строка_читаема_в_журнале() {
        let spec = block_ip("10.0.0.7");
        let text = spec.display();

        assert!(text.starts_with("netsh advfirewall"));
        // Аргумент содержит пробелы, поэтому целиком заключается
        // в кавычки: иначе запись в журнале читалась бы неоднозначно
        // и нельзя было бы понять, где кончается одно значение.
        assert!(text.contains("\"name=Alyvion block 10.0.0.7\""));
    }

    #[test]
    fn снимок_процессов_берётся_в_csv() {
        // CSV, а не таблица: колонки разделены запятыми, и разбор
        // не зависит от ширины столбцов, которая плавает.
        let spec = list_processes();
        assert_eq!(spec.program, "tasklist");
        assert!(spec.args.contains(&"CSV".to_string()));
    }

    #[test]
    fn проверка_процесса_фильтрует_по_pid() {
        let spec = process_query(1234);
        assert!(spec.args.contains(&"PID eq 1234".to_string()));
    }

    #[test]
    fn соединения_берутся_с_идентификаторами_процессов() {
        let spec = list_connections();
        assert_eq!(spec.program, "netstat");
        // Ключ -ano добавляет идентификатор процесса: без него
        // непонятно, какая программа держит соединение.
        assert!(spec.args.contains(&"-ano".to_string()));
    }
}
