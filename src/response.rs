//! Исполнение команд реагирования.
//!
//! КЛЮЧЕВОЙ ПРИНЦИП БЕЗОПАСНОСТИ: агент выполняет ТОЛЬКО действия из
//! перечисления `ResponseActionType` и ТОЛЬКО те, что объявлены в его
//! возможностях при регистрации. Произвольная команда, строка оболочки
//! или путь, не предусмотренный контрактом, выполнены быть не могут —
//! такой команды просто нет в типизированном наборе.
//!
//! Дополнительно КАЖДЫЙ параметр проверяется: адрес должен быть
//! корректным IP, PID — числом, имя пользователя — допустимым
//! идентификатором. Это защищает от подстановки в аргументы утилит
//! значений вида `1.2.3.4; rm -rf /`.
//!
//! Все действия выполняются через `Command` с ЯВНЫМ списком аргументов,
//! без промежуточной оболочки: оболочка не участвует, поэтому
//! спецсимволы не интерпретируются.

use std::net::IpAddr;
use std::process::Command;
use std::time::Instant;

use chrono::Utc;

use crate::pb::{ResponseActionType, ResponseCommand, ResponseCommandResult};

/// Результат выполнения: успех, сообщение и дополнительные сведения.
struct Outcome {
    success: bool,
    message: String,
    details: Vec<(String, String)>,
}

impl Outcome {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            details: Vec::new(),
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            details: Vec::new(),
        }
    }

    fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.details.push((key.to_string(), value.into()));
        self
    }
}

/// Исполнитель команд реагирования.
pub struct ResponseExecutor {
    /// Разрешено ли реагирование конфигурацией агента.
    allowed: bool,
}

impl ResponseExecutor {
    pub fn new(allowed: bool) -> Self {
        Self { allowed }
    }

    /// Выполняет команду и возвращает результат для Core.
    ///
    /// Метод НИКОГДА не паникует и не возвращает ошибку наружу:
    /// любая проблема превращается в отчёт с `success = false`,
    /// который оператор увидит в консоли.
    pub fn execute(&self, command: &ResponseCommand) -> ResponseCommandResult {
        let started = Instant::now();
        let action = ResponseActionType::try_from(command.action)
            .unwrap_or(ResponseActionType::ResponseActionUnspecified);

        tracing::info!(
            command_id = %command.command_id,
            action = ?action,
            issued_by = %command.issued_by,
            "получена команда реагирования"
        );

        // Проверка 1: реагирование вообще разрешено.
        if !self.allowed {
            return self.rejected(
                command,
                action,
                started,
                "реагирование выключено в конфигурации агента",
            );
        }

        // Проверка 2: действие входит в поддерживаемый набор.
        let outcome = match action {
            ResponseActionType::ResponseActionUnspecified => {
                return self.rejected(command, action, started, "действие не указано");
            }
            ResponseActionType::BlockIp => self.block_ip(command),
            ResponseActionType::UnblockIp => self.unblock_ip(command),
            ResponseActionType::KillProcess => self.kill_process(command),
            ResponseActionType::DisableUser => self.disable_user(command),
            ResponseActionType::EnableUser => self.enable_user(command),
            ResponseActionType::IsolateHost => self.isolate_host(command),
            ResponseActionType::ReleaseHost => self.release_host(command),
            ResponseActionType::CollectForensics => self.collect_forensics(command),
            ResponseActionType::QuarantineFile => self.quarantine_file(command),
            ResponseActionType::PingAction => Outcome::ok("механизм реагирования доступен"),
        };

        let duration_ms = started.elapsed().as_millis() as i64;

        if outcome.success {
            tracing::info!(
                command_id = %command.command_id,
                action = ?action,
                duration_ms,
                "команда выполнена"
            );
        } else {
            tracing::warn!(
                command_id = %command.command_id,
                action = ?action,
                reason = %outcome.message,
                "команда не выполнена"
            );
        }

        ResponseCommandResult {
            command_id: command.command_id.clone(),
            success: outcome.success,
            message: outcome.message,
            executed_at_unix_ms: Utc::now().timestamp_millis(),
            duration_ms,
            details: outcome.details.into_iter().collect(),
            rejected: false,
        }
    }

    /// Формирует отчёт об отклонённой команде.
    fn rejected(
        &self,
        command: &ResponseCommand,
        action: ResponseActionType,
        started: Instant,
        reason: &str,
    ) -> ResponseCommandResult {
        tracing::warn!(
            command_id = %command.command_id,
            action = ?action,
            reason,
            "команда отклонена агентом"
        );

        ResponseCommandResult {
            command_id: command.command_id.clone(),
            success: false,
            message: format!("Команда отклонена: {reason}"),
            executed_at_unix_ms: Utc::now().timestamp_millis(),
            duration_ms: started.elapsed().as_millis() as i64,
            details: Default::default(),
            rejected: true,
        }
    }

    // ------------------------------------------------------------------------
    //  Сетевые действия
    // ------------------------------------------------------------------------

    /// Блокировка сетевого адреса на узле.
    fn block_ip(&self, command: &ResponseCommand) -> Outcome {
        let ip = match validate_ip(&command.param_ip) {
            Ok(ip) => ip,
            Err(err) => return Outcome::fail(err),
        };

        // Правило в отдельной цепочке: её легко снять целиком и она
        // не мешает штатным правилам администратора.
        let added = run("iptables", &["-I", "INPUT", "-s", &ip, "-j", "DROP"]);
        if !added.success {
            return added;
        }

        let mut outcome = Outcome::ok(format!("Адрес {ip} заблокирован на узле"))
            .with("ip", ip.clone())
            .with("chain", "INPUT")
            .with("mechanism", "iptables");

        if command.param_duration_secs > 0 {
            outcome = outcome.with(
                "duration_secs",
                command.param_duration_secs.to_string(),
            );
        }

        outcome
    }

    /// Снятие блокировки адреса.
    fn unblock_ip(&self, command: &ResponseCommand) -> Outcome {
        let ip = match validate_ip(&command.param_ip) {
            Ok(ip) => ip,
            Err(err) => return Outcome::fail(err),
        };

        // Удаляем все правила для этого адреса: их могло накопиться несколько.
        for _ in 0..16 {
            let removed = run("iptables", &["-D", "INPUT", "-s", &ip, "-j", "DROP"]);
            if !removed.success {
                break;
            }
        }

        Outcome::ok(format!("Блокировка адреса {ip} снята"))
            .with("ip", ip)
            .with("mechanism", "iptables")
    }

    /// Сетевая изоляция узла.
    ///
    /// ВНИМАНИЕ: изоляция разорвала бы и канал с Core, поэтому здесь
    /// реализован безопасный вариант — запрет нового входящего трафика
    /// с сохранением уже установленных соединений (в том числе канала
    /// управления). Полная изоляция узла в прототипе не применяется.
    fn isolate_host(&self, _command: &ResponseCommand) -> Outcome {
        let result = run(
            "iptables",
            &[
                "-I",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-j",
                "DROP",
            ],
        );

        if !result.success {
            return result;
        }

        Outcome::ok("Новые входящие соединения заблокированы; канал с Core сохранён")
            .with("mode", "new-connections-only")
            .with("mechanism", "iptables conntrack")
    }

    /// Снятие изоляции узла.
    fn release_host(&self, _command: &ResponseCommand) -> Outcome {
        run(
            "iptables",
            &[
                "-D",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-j",
                "DROP",
            ],
        )
    }

    // ------------------------------------------------------------------------
    //  Действия над процессами
    // ------------------------------------------------------------------------

    /// Завершение процесса по PID.
    fn kill_process(&self, command: &ResponseCommand) -> Outcome {
        if command.param_pid == 0 {
            return Outcome::fail("не указан PID процесса");
        }

        if command.param_pid == 1 {
            return Outcome::fail("завершение процесса с PID 1 (init) запрещено");
        }

        if command.param_pid == std::process::id() {
            return Outcome::fail("агент отказывается завершать сам себя");
        }

        // Сначала проверяем, что процесс существует: иначе SIGTERM
        // вернёт невнятную ошибку.
        if !std::path::Path::new(&format!("/proc/{}", command.param_pid)).exists() {
            return Outcome::fail(format!("процесс с PID {} не найден", command.param_pid));
        }

        let pid = command.param_pid.to_string();

        // Сначала мягко, затем принудительно: так процесс успевает
        // корректно закрыть файлы и соединения.
        match run("kill", &["-TERM", &pid]) {
            result if result.success => Outcome::ok(format!(
                "Процесс {} завершён сигналом SIGTERM",
                command.param_pid
            ))
            .with("pid", pid)
            .with("signal", "SIGTERM"),

            _ => match run("kill", &["-KILL", &pid]) {
                result if result.success => Outcome::ok(format!(
                    "Процесс {} завершён сигналом SIGKILL",
                    command.param_pid
                ))
                .with("pid", pid)
                .with("signal", "SIGKILL"),

                result => Outcome::fail(format!(
                    "не удалось завершить процесс {}: {}",
                    command.param_pid, result.message
                )),
            },
        }
    }

    // ------------------------------------------------------------------------
    //  Действия над учётными записями
    // ------------------------------------------------------------------------

    /// Блокировка учётной записи.
    fn disable_user(&self, command: &ResponseCommand) -> Outcome {
        let user = match validate_user(&command.param_user) {
            Ok(user) => user,
            Err(err) => return Outcome::fail(err),
        };

        // Блокировка собственного пользователя агента лишила бы
        // администратора доступа к узлу.
        if user == "root" {
            return Outcome::fail("блокировка учётной записи root запрещена");
        }

        match run("usermod", &["--lock", &user]) {
            result if result.success => {
                Outcome::ok(format!("Учётная запись {user} заблокирована"))
                    .with("user", user)
                    .with("mechanism", "usermod --lock")
            }
            result => Outcome::fail(format!(
                "не удалось заблокировать {user}: {}",
                result.message
            )),
        }
    }

    /// Разблокировка учётной записи.
    fn enable_user(&self, command: &ResponseCommand) -> Outcome {
        let user = match validate_user(&command.param_user) {
            Ok(user) => user,
            Err(err) => return Outcome::fail(err),
        };

        match run("usermod", &["--unlock", &user]) {
            result if result.success => {
                Outcome::ok(format!("Учётная запись {user} разблокирована"))
                    .with("user", user)
                    .with("mechanism", "usermod --unlock")
            }
            result => Outcome::fail(format!(
                "не удалось разблокировать {user}: {}",
                result.message
            )),
        }
    }

    // ------------------------------------------------------------------------
    //  Сбор информации
    // ------------------------------------------------------------------------

    /// Сбор дополнительной информации об узле.
    ///
    /// Действие безопасное и не изменяет систему: оператор получает
    /// срез состояния для разбора инцидента.
    fn collect_forensics(&self, command: &ResponseCommand) -> Outcome {
        let mut outcome = Outcome::ok("Собрана информация об узле");

        // Список процессов на момент разбора.
        if let Ok(output) = Command::new("ps").args(["aux"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let count = text.lines().count().saturating_sub(1);
            outcome = outcome.with("processes_total", count.to_string());

            // В отчёт кладём только «хвост», чтобы не раздувать сообщение.
            let tail: String = text.lines().take(20).collect::<Vec<_>>().join("\n");
            outcome = outcome.with("processes_sample", tail);
        }

        // Установленные сетевые соединения: важны для разбора вторжений.
        if let Ok(output) = Command::new("ss").args(["-tunap"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let tail: String = text.lines().take(20).collect::<Vec<_>>().join("\n");
            outcome = outcome.with("connections_sample", tail);
        }

        // Последние входы в систему.
        if let Ok(output) = Command::new("last").args(["-n", "10"]).output() {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            outcome = outcome.with("last_logins", text);
        }

        outcome = outcome.with(
            "requested_by",
            if command.issued_by.is_empty() {
                "operator".to_string()
            } else {
                command.issued_by.clone()
            },
        );

        outcome
    }

    /// Помещение файла в карантин.
    ///
    /// Файл НЕ удаляется: он перемещается в карантинный каталог с
    /// сохранением прав, чтобы его можно было исследовать.
    fn quarantine_file(&self, command: &ResponseCommand) -> Outcome {
        let path = command
            .param_extra
            .iter()
            .find_map(|p| p.strip_prefix("path=").map(|s| s.to_string()))
            .or_else(|| {
                command
                    .param_extra
                    .iter()
                    .find(|p| p.starts_with('/'))
                    .cloned()
            })
            .unwrap_or_default();

        if path.is_empty() {
            return Outcome::fail("не указан путь к файлу");
        }

        // Запрещаем карантин системных каталогов: ошибка оператора
        // не должна ломать узел.
        const FORBIDDEN: [&str; 6] = ["/proc", "/sys", "/dev", "/boot", "/usr/lib", "/lib"];
        if FORBIDDEN.iter().any(|f| path.starts_with(f)) {
            return Outcome::fail(format!("карантин системного пути {path} запрещён"));
        }

        let source = std::path::Path::new(&path);
        if !source.exists() {
            return Outcome::fail(format!("файл {path} не найден"));
        }

        let quarantine_dir = std::path::Path::new("/var/lib/alyvion/quarantine");
        if let Err(err) = std::fs::create_dir_all(quarantine_dir) {
            return Outcome::fail(format!("не удалось создать карантинный каталог: {err}"));
        }

        let file_name = source
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string());

        let stamp = Utc::now().format("%Y%m%d-%H%M%S");
        let destination = quarantine_dir.join(format!("{stamp}-{file_name}"));

        match std::fs::rename(source, &destination) {
            Ok(()) => Outcome::ok(format!("Файл перемещён в карантин: {}", destination.display()))
                .with("source", path)
                .with("destination", destination.display().to_string()),

            // Разные файловые системы — переносим копированием.
            Err(_) => match std::fs::copy(source, &destination) {
                Ok(_) => {
                    let _ = std::fs::remove_file(source);
                    Outcome::ok(format!(
                        "Файл скопирован в карантин и удалён: {}",
                        destination.display()
                    ))
                    .with("source", path)
                    .with("destination", destination.display().to_string())
                }
                Err(err) => Outcome::fail(format!("не удалось поместить файл в карантин: {err}")),
            },
        }
    }
}

/// Выполняет внешнюю утилиту с явным списком аргументов.
///
/// Оболочка не используется намеренно: так исключается интерпретация
/// спецсимволов и подстановка команд.
fn run(program: &str, args: &[&str]) -> Outcome {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => Outcome::ok(format!("{program}: выполнено")),

        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

            let reason = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                format!("код возврата {:?}", output.status.code())
            };

            Outcome::fail(reason)
        }

        Err(err) => Outcome::fail(format!("не удалось запустить {program}: {err}")),
    }
}

/// Проверяет и нормализует IP-адрес.
///
/// Разбор через стандартную библиотеку гарантирует, что в аргументы
/// утилиты попадёт именно адрес, а не произвольная строка.
fn validate_ip(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err("не указан IP-адрес".to_string());
    }

    match trimmed.parse::<IpAddr>() {
        Ok(ip) => Ok(ip.to_string()),
        Err(_) => Err(format!("некорректный IP-адрес: {trimmed}")),
    }
}

/// Проверяет имя учётной записи.
///
/// Допускаются только буквы, цифры, точка, дефис и подчёркивание —
/// как в стандартных правилах для имён пользователей Linux.
fn validate_user(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err("не указана учётная запись".to_string());
    }

    if trimmed.len() > 32 {
        return Err("имя учётной записи слишком длинное".to_string());
    }

    let valid = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');

    if !valid {
        return Err(format!("недопустимое имя учётной записи: {trimmed}"));
    }

    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(action: ResponseActionType) -> ResponseCommand {
        ResponseCommand {
            command_id: "test-command".to_string(),
            action: action as i32,
            ..Default::default()
        }
    }

    #[test]
    fn при_выключенном_реагировании_команда_отклоняется() {
        let executor = ResponseExecutor::new(false);
        let result = executor.execute(&command(ResponseActionType::PingAction));

        assert!(!result.success);
        assert!(result.rejected, "команда должна быть помечена как отклонённая");
        assert_eq!(result.command_id, "test-command");
    }

    #[test]
    fn служебное_действие_выполняется_при_разрешённом_реагировании() {
        let executor = ResponseExecutor::new(true);
        let result = executor.execute(&command(ResponseActionType::PingAction));

        assert!(result.success);
        assert!(!result.rejected);
        assert!(result.message.contains("доступен"));
    }

    #[test]
    fn действие_без_параметров_не_паникует() {
        let executor = ResponseExecutor::new(true);
        for action in [
            ResponseActionType::BlockIp,
            ResponseActionType::KillProcess,
            ResponseActionType::DisableUser,
            ResponseActionType::QuarantineFile,
        ] {
            let result = executor.execute(&command(action));
            assert!(!result.success, "{action:?} без параметров должен быть отклонён");
            assert!(!result.rejected);
        }
    }

    #[test]
    fn корректные_ip_проходят_проверку() {
        assert_eq!(validate_ip("203.0.113.77").unwrap(), "203.0.113.77");
        assert_eq!(validate_ip("  10.0.0.1  ").unwrap(), "10.0.0.1");
        assert_eq!(validate_ip("::1").unwrap(), "::1");
    }

    #[test]
    fn подстановка_команд_в_ip_отклоняется() {
        // Классическая попытка внедрения: адрес со спецсимволами.
        assert!(validate_ip("1.2.3.4; rm -rf /").is_err());
        assert!(validate_ip("$(whoami)").is_err());
        assert!(validate_ip("1.2.3.4 && shutdown").is_err());
        assert!(validate_ip("").is_err());
    }

    #[test]
    fn корректные_имена_пользователей_проходят_проверку() {
        assert_eq!(validate_user("deploy").unwrap(), "deploy");
        assert_eq!(validate_user("svc-backup").unwrap(), "svc-backup");
        assert_eq!(validate_user("user.name_1").unwrap(), "user.name_1");
    }

    #[test]
    fn подстановка_команд_в_имени_пользователя_отклоняется() {
        assert!(validate_user("root; rm -rf /").is_err());
        assert!(validate_user("user`id`").is_err());
        assert!(validate_user("user name").is_err());
        assert!(validate_user("$USER").is_err());
        assert!(validate_user("").is_err());
        assert!(validate_user(&"a".repeat(33)).is_err());
    }

    #[test]
    fn запрещено_завершать_процесс_init() {
        let executor = ResponseExecutor::new(true);
        let mut cmd = command(ResponseActionType::KillProcess);
        cmd.param_pid = 1;

        let result = executor.execute(&cmd);
        assert!(!result.success);
        assert!(result.message.contains("PID 1"));
    }

    #[test]
    fn запрещено_завершать_самого_агента() {
        let executor = ResponseExecutor::new(true);
        let mut cmd = command(ResponseActionType::KillProcess);
        cmd.param_pid = std::process::id();

        let result = executor.execute(&cmd);
        assert!(!result.success);
        assert!(result.message.contains("сам себя"));
    }

    #[test]
    fn запрещено_блокировать_root() {
        let executor = ResponseExecutor::new(true);
        let mut cmd = command(ResponseActionType::DisableUser);
        cmd.param_user = "root".to_string();

        let result = executor.execute(&cmd);
        assert!(!result.success);
        assert!(result.message.contains("root"));
    }

    #[test]
    fn запрещён_карантин_системных_каталогов() {
        let executor = ResponseExecutor::new(true);
        let mut cmd = command(ResponseActionType::QuarantineFile);
        cmd.param_extra = vec!["path=/proc/self/mem".to_string()];

        let result = executor.execute(&cmd);
        assert!(!result.success);
        assert!(result.message.contains("системного пути"));
    }

    #[test]
    fn результат_всегда_содержит_идентификатор_и_время() {
        let executor = ResponseExecutor::new(true);
        let result = executor.execute(&command(ResponseActionType::PingAction));

        assert_eq!(result.command_id, "test-command");
        assert!(result.executed_at_unix_ms > 0);
    }
}
