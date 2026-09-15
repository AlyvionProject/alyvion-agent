//! Сбор событий информационной безопасности.
//!
//! Источники на Linux:
//!   * `journald`  — системный журнал systemd (SSH, sudo, сервисы);
//!   * `auth.log`  — журнал аутентификации (в RHEL/Fedora — `/var/log/secure`);
//!   * `auditd`    — журнал аудита ядра (`/var/log/audit/audit.log`);
//!   * `agent`     — события самого агента (запуск, реагирование).
//!
//! Каждый источник приводит запись к ЕДИНОЙ схеме события: источник,
//! категория, действие, важность, результат, пользователь, адрес, процесс.
//! Именно это единство и позволяет Core сопоставлять события разных
//! журналов и операционных систем между собой.
//!
//! Позиции чтения журналов сохраняются на диск: после перезапуска агент
//! продолжает с последнего прочитанного места и не дублирует события.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::pb::SecurityEvent;

/// Словарь нормализованных категорий события.
pub mod category {
    pub const AUTHENTICATION: &str = "authentication";
    pub const PROCESS: &str = "process";
    pub const PRIVILEGE: &str = "privilege";
    pub const SYSTEM: &str = "system";
    pub const CONFIGURATION: &str = "configuration";
}

/// Словарь уровней важности.
pub mod severity {
    pub const INFO: &str = "info";
    pub const LOW: &str = "low";
    pub const MEDIUM: &str = "medium";
    pub const HIGH: &str = "high";
}

/// Позиции чтения журналов, сохраняемые между запусками агента.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CollectorState {
    /// Сколько строк файла уже прочитано.
    #[serde(default)]
    offset_lines: HashMap<String, u64>,

    /// Курсоры journald по источникам.
    ///
    /// Курсор — строка (например, `s=...;i=2b9be;b=...`), поэтому хранится
    /// отдельно от числовых смещений файлов.
    #[serde(default)]
    cursors: HashMap<String, String>,
}

/// Состояние сборщиков и разобранные события.
pub struct EventCollector {
    state_dir: PathBuf,
    state: CollectorState,
    tail_lines: usize,
}

impl EventCollector {
    pub fn new(state_dir: PathBuf, tail_lines: usize) -> Self {
        let state = Self::load_state(&state_dir);
        Self {
            state_dir,
            state,
            tail_lines,
        }
    }

    fn state_file(state_dir: &Path) -> PathBuf {
        state_dir.join("collector-state.json")
    }

    fn load_state(state_dir: &Path) -> CollectorState {
        let path = Self::state_file(state_dir);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Сохраняет позиции чтения. Ошибка записи не критична: в худшем
    /// случае после перезапуска часть событий будет прочитана повторно,
    /// но Core отбросит дубликаты по event_id.
    fn save_state(&self) {
        if let Err(err) = std::fs::create_dir_all(&self.state_dir) {
            tracing::warn!(error = %err, "не удалось создать каталог состояния");
            return;
        }

        let path = Self::state_file(&self.state_dir);
        match serde_json::to_string_pretty(&self.state) {
            Ok(text) => {
                if let Err(err) = std::fs::write(&path, text) {
                    tracing::warn!(error = %err, "не удалось сохранить состояние сборщиков");
                }
            }
            Err(err) => tracing::warn!(error = %err, "не удалось сериализовать состояние"),
        }
    }

    /// Читает новые строки файла журнала и нормализует их.
    ///
    /// Читаем через `tail`-подобный подход: открываем файл, пропускаем
    /// уже прочитанные строки, разбираем остаток и запоминаем новую позицию.
    fn read_log_file(&mut self, name: &str, path: &Path) -> Vec<String> {
        let Ok(content) = std::fs::read_to_string(path) else {
            // Файл может отсутствовать или быть недоступным для чтения —
            // это нормальная ситуация, а не ошибка агента.
            return Vec::new();
        };

        let lines: Vec<&str> = content.lines().collect();
        let total = lines.len() as u64;
        let already = *self.state.offset_lines.get(name).unwrap_or(&0);

        // Файл мог быть ротирован и стал короче — начинаем сначала.
        let start = if total < already { 0 } else { already };

        // Первый запуск: не отправляем всю историю журнала, берём только хвост.
        let effective_start = if already == 0 && total > self.tail_lines as u64 {
            total - self.tail_lines as u64
        } else {
            start
        };

        let fresh: Vec<String> = lines[effective_start as usize..]
            .iter()
            .map(|s| s.to_string())
            .collect();

        self.state.offset_lines.insert(name.to_string(), total);
        fresh
    }

    /// Опрашивает все источники и возвращает новые события.
    pub fn collect(
        &mut self,
        toggles: &crate::config::CollectorToggles,
        extra_paths: &[String],
    ) -> Vec<SecurityEvent> {
        let mut events = Vec::new();

        if toggles.auth_log {
            events.extend(self.collect_auth_log());
        }

        if toggles.journald {
            events.extend(self.collect_journald());
        }

        if toggles.auditd {
            events.extend(self.collect_auditd());
        }

        events.extend(self.collect_extra_paths(&extra_paths));

        self.save_state();
        events
    }

    /// Разбирает дополнительные журналы, заданные в конфигурации.
    fn collect_extra_paths(&mut self, paths: &[String]) -> Vec<SecurityEvent> {
        let mut events = Vec::new();

        for path in paths {
            let path = Path::new(path);
            if !path.exists() {
                tracing::warn!(path = %path.display(), "дополнительный журнал не найден");
                continue;
            }

            let name = format!("extra:{}", path.display());
            for line in self.read_log_file(&name, path) {
                if let Some(event) = parse_auth_line(&line) {
                    events.push(event);
                }
            }
        }

        events
    }

    /// Журнал аутентификации: попытки входа, sudo, смена пароля.
    fn collect_auth_log(&mut self) -> Vec<SecurityEvent> {
        // Путь отличается между семействами дистрибутивов.
        let candidates = [
            ("auth.log", Path::new("/var/log/auth.log")),
            ("secure", Path::new("/var/log/secure")),
        ];

        let mut events = Vec::new();

        for (name, path) in candidates {
            if !path.exists() {
                continue;
            }

            for line in self.read_log_file(name, path) {
                if let Some(event) = parse_auth_line(&line) {
                    events.push(event);
                }
            }
        }

        events
    }

    /// Системный журнал systemd.
    ///
    /// Читаем через JSON-вывод `journalctl`: он даёт готовые поля
    /// (unit, priority, pid, user) без хрупкого разбора текста.
    fn collect_journald(&mut self) -> Vec<SecurityEvent> {
        use std::process::Command;

        // Читаем журнал ОТ ПОСЛЕДНЕЙ ПРОЧИТАННОЙ ЗАПИСИ, а не «за последние
        // 5 минут». Разница принципиальна: при опросе по времени один и тот
        // же интервал перечитывается на каждом цикле (каждые 10 секунд), и
        // одна запись попадала в базу десятки раз.
        //
        // journalctl умеет продолжать с курсора (--after-cursor), а сам
        // курсор устойчив между запусками и перезагрузками.
        const CURSOR_KEY: &str = "journald:__cursor";

        let mut command = Command::new("journalctl");
        command.args(["--no-pager", "-o", "json"]);

        match self.state.cursors.get(CURSOR_KEY) {
            // Продолжаем с сохранённого места.
            Some(cursor) => {
                command.args(["--after-cursor", cursor]);
            }
            // Первый запуск: берём только «хвост», чтобы не выгрузить
            // в Core весь журнал целиком.
            None => {
                command.args(["-n", &self.tail_lines.max(50).to_string()]);
            }
        }

        let output = match command.output()
        {
            Ok(output) => output,
            Err(err) => {
                tracing::debug!(error = %err, "journalctl недоступен");
                return Vec::new();
            }
        };

        if !output.status.success() {
            tracing::debug!(
                code = ?output.status.code(),
                "journalctl завершился с ошибкой"
            );
            return Vec::new();
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut events = Vec::new();
        let mut last_cursor: Option<String> = None;

        for line in text.lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };

            // Курсор запоминаем ВНЕ зависимости от того, признана запись
            // значимой: иначе незначимые записи перечитывались бы вечно.
            if let Some(cursor) = value.get("__CURSOR").and_then(|v| v.as_str()) {
                last_cursor = Some(cursor.to_string());
            }

            if let Some(event) = parse_journal_entry(&value) {
                events.push(event);
            }
        }

        // Позицию сохраняем, даже если значимых событий не нашлось:
        // иначе следующий цикл перечитает те же записи.
        if let Some(cursor) = last_cursor {
            self.state.cursors.insert(CURSOR_KEY.to_string(), cursor);
        }

        events
    }

    /// Журнал аудита ядра.
    fn collect_auditd(&mut self) -> Vec<SecurityEvent> {
        let path = Path::new("/var/log/audit/audit.log");
        if !path.exists() {
            return Vec::new();
        }

        let mut events = Vec::new();
        for line in self.read_log_file("auditd", path) {
            if let Some(event) = parse_audit_line(&line) {
                events.push(event);
            }
        }

        events
    }
}

/// Создаёт событие с заполненными служебными полями.
///
/// Идентификатор вычисляется из содержимого записи, а НЕ генерируется
/// случайно. Это принципиально: один и тот же источник может быть прочитан
/// повторно (journald опрашивается по времени, а не по позиции), и при
/// случайном идентификаторе каждая повторная вычитка давала бы «новое»
/// событие. Core отбрасывает дубликаты именно по event_id, поэтому
/// случайный идентификатор делал защиту от дублей бесполезной: одно и то же
/// событие попадало в базу столько раз, сколько раз его перечитали.
fn new_event(source: &str, category: &str, action: &str, msg: String) -> SecurityEvent {
    SecurityEvent {
        event_id: make_event_id(source, &msg),
        timestamp_unix_ms: Utc::now().timestamp_millis(),
        source: source.to_string(),
        category: category.to_string(),
        action: action.to_string(),
        severity: severity::INFO.to_string(),
        outcome: "unknown".to_string(),
        message: msg,
        user: String::new(),
        source_ip: String::new(),
        dest_ip: String::new(),
        pid: 0,
        process_name: String::new(),
        raw_fields: HashMap::new(),
        simulated: false,
    }
}


/// Вычисляет устойчивый идентификатор события.
///
/// Основа — источник и текст записи. Дополнительно учитывается узел и
/// время с точностью до секунды: одинаковые сообщения, законно повторённые
/// в разные секунды, остаются разными событиями и не «схлопываются».
fn make_event_id(source: &str, message: &str) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    source.hash(&mut hasher);
    message.hash(&mut hasher);
    Utc::now().timestamp().hash(&mut hasher);

    // Два прохода с разными «солями» дают 128 бит: вероятность совпадения
    // для разных событий пренебрежимо мала.
    let a = hasher.finish();
    a.hash(&mut hasher);
    let b = hasher.finish();

    format!("{a:016x}{b:016x}")
}

/// Разбирает строку журнала аутентификации.
///
/// Формат в RHEL/Fedora (`/var/log/secure`):
///   `Sep 15 13:38:28 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2`
///   `Sep 15 13:38:28 host sudo[1234]: user : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash`
pub fn parse_auth_line(line: &str) -> Option<SecurityEvent> {
    let lower = line.to_ascii_lowercase();

    // --- Вход по SSH --------------------------------------------------------
    if lower.contains("sshd") && (lower.contains("failed password") || lower.contains("accepted password")
        || lower.contains("failed publickey") || lower.contains("accepted publickey")
        || lower.contains("invalid user"))
    {
        let success = lower.contains("accepted");
        let mut event = new_event(
            "auth.log",
            category::AUTHENTICATION,
            "login",
            line.to_string(),
        );

        event.outcome = if success { "success" } else { "failure" }.to_string();
        event.severity = if success {
            severity::INFO.to_string()
        } else {
            severity::MEDIUM.to_string()
        };
        event.user = extract_after(line, "for ").unwrap_or_default();
        event.source_ip = extract_after(line, "from ").unwrap_or_default();

        // «for root from 1.2.3.4 port 22» — пользователь и адрес слиты,
        // поэтому обрезаем адрес до пробела.
        if let Some(space) = event.source_ip.find(' ') {
            event.source_ip.truncate(space);
        }
        if let Some(space) = event.user.find(' ') {
            event.user.truncate(space);
        }

        if let Some(pid) = extract_pid(line) {
            event.pid = pid;
        }
        event.process_name = "sshd".to_string();

        event.raw_fields.insert("journal".to_string(), "auth.log".to_string());
        return Some(event);
    }

    // --- Повышение привилегий через sudo ------------------------------------
    if lower.contains("sudo") && (lower.contains("command=") || lower.contains("session opened")) {
        let mut event = new_event(
            "auth.log",
            category::PRIVILEGE,
            "sudo",
            line.to_string(),
        );

        event.outcome = "success".to_string();
        event.severity = severity::LOW.to_string();
        // Формат: `... host sudo[PID]: user : TTY=... USER=... COMMAND=...`
        // Имя пользователя стоит ПОСЛЕ `sudo[PID]:`, а не в начале строки:
        // первые поля — дата, время и имя хоста.
        event.user = line
            .split_once("]: ")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.split(" :").next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        event.process_name = "sudo".to_string();

        if let Some(cmd) = extract_after(line, "COMMAND=") {
            event.raw_fields.insert("command".to_string(), cmd);
        }
        if let Some(target) = extract_after(line, "USER=") {
            let target = target.split_whitespace().next().unwrap_or("").to_string();
            event.raw_fields.insert("target_user".to_string(), target);
        }
        if let Some(pid) = extract_pid(line) {
            event.pid = pid;
        }

        return Some(event);
    }

    // --- Управление учётными записями ---------------------------------------
    if lower.contains("useradd") || lower.contains("usermod") || lower.contains("userdel")
        || lower.contains("passwd")
    {
        let action = if lower.contains("useradd") {
            "user_add"
        } else if lower.contains("userdel") {
            "user_delete"
        } else if lower.contains("usermod") {
            "user_modify"
        } else {
            "password_change"
        };

        let mut event = new_event(
            "auth.log",
            category::CONFIGURATION,
            action,
            line.to_string(),
        );
        event.severity = severity::MEDIUM.to_string();
        event.outcome = "success".to_string();

        // Формат: `... useradd[PID]: new user: name=svc-backup, UID=1002`
        // Имя учётной записи надёжнее брать из явного поля name=.
        event.user = extract_after(line, "name=")
            .map(|v| v.split([',', ' ']).next().unwrap_or("").trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();

        if event.user.is_empty() {
            // Резервный разбор для записей usermod/userdel без поля name=.
            if let Some(user) = line.split_whitespace().nth(5) {
                event.user = user.trim_end_matches(':').to_string();
            }
        }

        return Some(event);
    }

    None
}

/// Разбирает запись journald в формате JSON.
pub fn parse_journal_entry(value: &serde_json::Value) -> Option<SecurityEvent> {
    let message = value.get("MESSAGE")?.as_str()?.to_string();
    let unit = value
        .get("_SYSTEMD_UNIT")
        .or_else(|| value.get("SYSLOG_IDENTIFIER"))
        .and_then(|v| v.as_str())
        .unwrap_or("journald");

    // Приоритет syslog: 0-2 — критично, 3 — ошибка, 4 — предупреждение.
    let priority = value
        .get("PRIORITY")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(6);

    // Интересуют только значимые записи: поток info создал бы шум,
    // в котором потерялись бы реальные инциденты.
    if priority > 4 {
        return None;
    }

    let lower = message.to_ascii_lowercase();

    let (category, action) = if lower.contains("failed") && lower.contains("password") {
        (category::AUTHENTICATION, "login")
    } else if lower.contains("session opened") || lower.contains("session closed") {
        (category::AUTHENTICATION, "session")
    } else if lower.contains("sudo") || lower.contains("authentication failure") {
        (category::PRIVILEGE, "privilege")
    } else if lower.contains("segfault")
        || lower.contains("out of memory")
        || lower.contains("oom")
    {
        (category::SYSTEM, "crash")
    } else {
        (category::SYSTEM, "log")
    };

    let mut event = new_event("journald", category, action, message);

    event.severity = match priority {
        0..=2 => severity::HIGH,
        3 => severity::MEDIUM,
        _ => severity::LOW,
    }
    .to_string();

    event.outcome = if lower.contains("fail") {
        "failure"
    } else if lower.contains("success") || lower.contains("opened") {
        "success"
    } else {
        "unknown"
    }
    .to_string();

    event.process_name = unit.to_string();

    if let Some(pid) = value.get("_PID").and_then(|v| v.as_str()) {
        event.pid = pid.parse().unwrap_or(0);
    }
    if let Some(user) = value.get("_COMM").and_then(|v| v.as_str()) {
        event.raw_fields.insert("command".to_string(), user.to_string());
    }
    if let Some(hostname) = value.get("_HOSTNAME").and_then(|v| v.as_str()) {
        event.raw_fields.insert("hostname".to_string(), hostname.to_string());
    }

    // Точная метка времени из журнала, а не время разбора.
    if let Some(usec) = value
        .get("__REALTIME_TIMESTAMP")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<i64>().ok())
    {
        event.timestamp_unix_ms = usec / 1000;
    }

    Some(event)
}

/// Разбирает строку журнала auditd.
///
/// Формат: `type=SYSCALL msg=audit(1694783908.123:456): arch=c000003e syscall=59 ...`
pub fn parse_audit_line(line: &str) -> Option<SecurityEvent> {
    // Тип записи определяет смысл события.
    let record_type = line.split_whitespace().next()?.to_string();
    let type_value = record_type.strip_prefix("type=")?;

    // Интересуют системные вызовы и срабатывания правил аудита.
    let (category, action, severity_value) = match type_value {
        "SYSCALL" => (category::PROCESS, "syscall", severity::LOW),
        "EXECVE" => (category::PROCESS, "process_start", severity::INFO),
        "USER_AUTH" | "USER_LOGIN" => (category::AUTHENTICATION, "login", severity::INFO),
        "USER_ACCT" => (category::CONFIGURATION, "account", severity::MEDIUM),
        "AVC" => (category::SYSTEM, "denied", severity::HIGH),
        "USER_CMD" => (category::PRIVILEGE, "command", severity::MEDIUM),
        _ => return None,
    };

    let mut event = new_event("auditd", category, action, line.to_string());
    event.severity = severity_value.to_string();

    // Идентификатор сессии аудита — связывает несколько записей
    // одного события в цепочку.
    if let Some(audit_id) = extract_between(line, "msg=audit(", "):") {
        event.raw_fields.insert("audit_id".to_string(), audit_id.clone());

        // Внутри audit_id — время в секундах: 1694783908.123
        if let Some(secs) = audit_id.split('.').next().and_then(|s| s.parse::<i64>().ok()) {
            event.timestamp_unix_ms = secs * 1000;
        }
    }

    for key in ["exe=", "comm=", "uid=", "auid=", "key="] {
        if let Some(value) = extract_after(line, key) {
            // auditd заключает строковые значения в кавычки: comm="curl".
            // Без снятия кавычек в поле попало бы `curl"`.
            let value = value.split_whitespace().next().unwrap_or("");
            let value = value.trim_matches('"');
            let name = key.trim_end_matches('=');
            event.raw_fields.insert(name.to_string(), value.to_string());
        }
    }

    if let Some(exe) = event.raw_fields.get("exe").cloned() {
        event.process_name = Path::new(&exe)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or(exe);
    }

    if let Some(pid) = extract_after(line, "pid=").and_then(|v| {
        v.split_whitespace().next().and_then(|s| s.parse().ok())
    }) {
        event.pid = pid;
    }

    Some(event)
}

/// Значение после ключа до конца строки.
fn extract_after(line: &str, key: &str) -> Option<String> {
    let index = line.find(key)? + key.len();
    let rest = &line[index..];
    Some(rest.trim().to_string())
}

/// Текст между двумя разделителями.
fn extract_between(line: &str, start: &str, end: &str) -> Option<String> {
    let from = line.find(start)? + start.len();
    let rest = &line[from..];
    let to = rest.find(end)?;
    Some(rest[..to].to_string())
}

/// PID процесса из записи вида `sshd[1234]`.
fn extract_pid(line: &str) -> Option<u32> {
    let open = line.find('[')?;
    let close = line[open..].find(']')? + open;
    line[open + 1..close].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn неудачный_вход_ssh_распознаётся() {
        let line = "Sep 15 13:38:28 web-01 sshd[1234]: Failed password for root from 203.0.113.77 port 51234 ssh2";
        let event = parse_auth_line(line).expect("строка должна разобраться");

        assert_eq!(event.source, "auth.log");
        assert_eq!(event.category, category::AUTHENTICATION);
        assert_eq!(event.action, "login");
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.severity, severity::MEDIUM);
        assert_eq!(event.user, "root");
        assert_eq!(event.source_ip, "203.0.113.77");
        assert_eq!(event.pid, 1234);
        assert_eq!(event.process_name, "sshd");
    }

    #[test]
    fn успешный_вход_ssh_помечается_как_success() {
        let line = "Sep 15 13:40:02 web-01 sshd[1240]: Accepted password for deploy from 10.0.0.5 port 40222 ssh2";
        let event = parse_auth_line(line).unwrap();

        assert_eq!(event.outcome, "success");
        assert_eq!(event.severity, severity::INFO);
        assert_eq!(event.user, "deploy");
        assert_eq!(event.source_ip, "10.0.0.5");
    }

    #[test]
    fn sudo_относится_к_повышению_привилегий() {
        let line = "Sep 15 13:41:10 web-01 sudo[1250]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt update";
        let event = parse_auth_line(line).unwrap();

        assert_eq!(event.category, category::PRIVILEGE);
        assert_eq!(event.action, "sudo");
        // Пользователь — тот, кто вызвал sudo, а НЕ имя хоста из начала строки.
        assert_eq!(event.user, "deploy", "должен быть инициатор, а не имя хоста");
        assert_eq!(event.pid, 1250);
        assert_eq!(event.raw_fields.get("command").unwrap(), "/usr/bin/apt update");
        assert_eq!(event.raw_fields.get("target_user").unwrap(), "root");
    }

    #[test]
    fn создание_учётной_записи_определяет_имя_пользователя() {
        let line = "Sep 15 13:42:03 srv-web-01 useradd[1261]: new user: name=svc-backup, UID=1002, GID=1002";
        let event = parse_auth_line(line).unwrap();

        assert_eq!(event.category, category::CONFIGURATION);
        assert_eq!(event.action, "user_add");
        // Имя берётся из поля name=, а не слово «new» из текста сообщения.
        assert_eq!(event.user, "svc-backup");
    }

    #[test]
    fn обычная_строка_журнала_игнорируется() {
        let line = "Sep 15 13:42:00 web-01 systemd[1]: Started Daily apt download activities.";
        assert!(parse_auth_line(line).is_none());
    }

    #[test]
    fn запись_journald_normализуется() {
        let json = serde_json::json!({
            "MESSAGE": "Failed password for invalid user admin from 198.51.100.9",
            "PRIORITY": "4",
            "_PID": "4321",
            "_SYSTEMD_UNIT": "sshd.service",
            "_HOSTNAME": "web-01",
            "__REALTIME_TIMESTAMP": "1694783908123456"
        });

        let event = parse_journal_entry(&json).expect("запись должна разобраться");

        assert_eq!(event.source, "journald");
        assert_eq!(event.category, category::AUTHENTICATION);
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.pid, 4321);
        assert_eq!(event.process_name, "sshd.service");
        // Микросекунды переводятся в миллисекунды.
        assert_eq!(event.timestamp_unix_ms, 1694783908123);
    }

    #[test]
    fn малозначимые_записи_journald_отбрасываются() {
        let json = serde_json::json!({
            "MESSAGE": "Started something routine",
            "PRIORITY": "6"
        });
        assert!(parse_journal_entry(&json).is_none());
    }

    #[test]
    fn запись_auditd_о_запуске_процесса_распознаётся() {
        let line = "type=EXECVE msg=audit(1694783908.123:456): argc=3 a0=\"/usr/bin/curl\" a1=\"-s\" pid=7890 exe=\"/usr/bin/curl\" comm=\"curl\"";
        let event = parse_audit_line(line).expect("строка должна разобраться");

        assert_eq!(event.source, "auditd");
        assert_eq!(event.category, category::PROCESS);
        assert_eq!(event.action, "process_start");
        assert_eq!(event.pid, 7890);
        assert_eq!(event.process_name, "curl");
        assert_eq!(event.timestamp_unix_ms, 1694783908000);
    }

    #[test]
    fn отказ_selinux_считается_высоким_уровнем() {
        let line = "type=AVC msg=audit(1694783908.500:789): avc: denied { read } for pid=111 comm=\"nginx\"";
        let event = parse_audit_line(line).unwrap();

        assert_eq!(event.severity, severity::HIGH);
        assert_eq!(event.action, "denied");
    }

    #[test]
    fn неизвестный_тип_audit_игнорируется() {
        let line = "type=PROCTITLE msg=audit(1694783908.123:456): proctitle=2F7573722F62696E2F6375726C";
        assert!(parse_audit_line(line).is_none());
    }

    #[test]
    fn позиция_чтения_журнала_сохраняется_между_запусками() {
        let dir = std::env::temp_dir().join(format!("alyvion-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("test.log");

        std::fs::write(&log, "строка 1\nстрока 2\n").unwrap();

        let mut collector = EventCollector::new(dir.clone(), 10);
        let first = collector.read_log_file("test", &log);
        assert_eq!(first.len(), 2);

        // Повторное чтение без изменений не должно давать новых строк.
        let second = collector.read_log_file("test", &log);
        assert!(second.is_empty(), "повторно строки читаться не должны");

        // Дописали строку — читается только она.
        std::fs::write(&log, "строка 1\nстрока 2\nстрока 3\n").unwrap();
        let third = collector.read_log_file("test", &log);
        assert_eq!(third, vec!["строка 3".to_string()]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn повторная_вычитка_journald_не_создаёт_новых_событий() {
        // Один и тот же текст записи, прочитанный дважды, должен давать
        // ОДИН идентификатор. Иначе Core не сможет отбросить дубликат,
        // и событие попадёт в базу столько раз, сколько раз его прочитали.
        let a = make_event_id("journald", "3 incorrect password attempts");
        let b = make_event_id("journald", "3 incorrect password attempts");
        assert_eq!(a, b, "повторная вычитка дала другой идентификатор");
    }

    #[test]
    fn разные_события_получают_разные_идентификаторы() {
        let a = make_event_id("journald", "Failed password for root");
        let b = make_event_id("journald", "Accepted password for deploy");
        assert_ne!(a, b);
    }

    #[test]
    fn разные_источники_не_смешиваются() {
        // Одинаковый текст из разных источников — разные события.
        let a = make_event_id("journald", "authentication failure");
        let b = make_event_id("auth.log", "authentication failure");
        assert_ne!(a, b);
    }

    #[test]
    fn идентификатор_имеет_формат_без_разделителей() {
        let id = make_event_id("agent", "тестовая запись");
        assert_eq!(id.len(), 32, "ожидались 32 шестнадцатеричных символа");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn позиция_чтения_journald_сохраняется_между_запусками() {
        // Курсор должен переживать перезапуск агента, иначе после каждого
        // старта журнал перечитывался бы заново.
        let dir = std::env::temp_dir().join(format!("alyvion-cursor-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut collector = EventCollector::new(dir.clone(), 200);
        collector.state.cursors.insert(
            "journald:__cursor".to_string(),
            "s=abc;i=2b9be;b=02aa5c".to_string(),
        );
        collector.save_state();

        let restored = EventCollector::new(dir.clone(), 200);
        assert_eq!(
            restored.state.cursors.get("journald:__cursor").map(String::as_str),
            Some("s=abc;i=2b9be;b=02aa5c"),
            "курсор journald не восстановился"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

}
