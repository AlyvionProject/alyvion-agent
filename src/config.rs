//! Конфигурация агента Alyvion.
//!
//! Источники значений (в порядке возрастания приоритета):
//!   1. значения по умолчанию;
//!   2. файл `alyvion-agent.toml` (путь задаётся `--config` или
//!      переменной `ALYVION_AGENT_CONFIG`);
//!   3. переменные окружения `ALYVION_*`.
//!
//! Такой порядок удобен при развёртывании: базовые параметры лежат
//! в файле рядом с агентом, а конкретный адрес Core подставляется
//! переменной окружения без правки файла.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Параметры подключения и режима работы агента.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Идентификатор узла. Пусто — взять имя хоста.
    /// Должен быть стабильным: Core связывает с ним всю историю.
    pub agent_id: String,

    /// Адрес gRPC-сервера Core, например `https://127.0.0.1:5050`.
    pub core_url: String,

    /// Одноразовый токен зачисления из панели оператора.
    pub enrollment_token: String,

    /// Корень УЦ Core (alyvion-ca.pem). Пусто — файл в state_dir/mtls.
    pub ca_file: String,

    /// Имя сервера для проверки TLS (SAN). Пусто — взять хост из URL.
    pub tls_server_name: String,

    /// Интервал отправки телеметрии, секунды.
    pub telemetry_interval_secs: u64,

    /// Интервал отправки heartbeat, секунды.
    pub heartbeat_interval_secs: u64,

    /// Интервал сбора событий безопасности, секунды.
    pub events_interval_secs: u64,

    /// Сколько последних строк журналов просматривать за один проход.
    pub log_tail_lines: usize,

    /// Ограничение числа процессов в снимке телеметрии.
    pub max_processes: usize,

    /// Интервал переподключения при обрыве связи, секунды.
    pub reconnect_delay_secs: u64,

    /// Каталог состояния (позиции чтения журналов).
    pub state_dir: PathBuf,

    /// Разрешить выполнение действий реагирования.
    ///
    /// По умолчанию ВЫКЛЮЧЕНО: включение означает, что агент начнёт
    /// менять систему (блокировать адреса, завершать процессы,
    /// блокировать учётные записи). Это осознанное решение администратора.
    pub allow_response_actions: bool,

    /// Источники событий, которые следует опрашивать.
    pub collectors: CollectorToggles,

    /// Дополнительные файлы журналов для разбора.
    ///
    /// Нужны для систем с нестандартными путями и для проверки сбора
    /// событий на стенде: агент разбирает их тем же правилом, что и
    /// журнал аутентификации.
    pub extra_log_paths: Vec<String>,
}

/// Включение отдельных источников событий.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorToggles {
    /// Системный журнал systemd (`journalctl`).
    pub journald: bool,
    /// Журнал аутентификации (`/var/log/secure` в RHEL/Fedora,
    /// `/var/log/auth.log` в Debian/Ubuntu).
    pub auth_log: bool,
    /// Журнал аудита ядра (`/var/log/audit/audit.log`).
    pub auditd: bool,
    /// События уровня агента: запуск, подключение, реагирование.
    pub agent: bool,

    /// Журнал событий Windows (Security, System, Application,
    /// PowerShell). На Linux настройка не действует: журнала Windows
    /// там нет, и сборщик возвращает пустой список.
    pub winevent: bool,

    /// Канал Sysmon.
    ///
    /// Выключен по умолчанию: Sysmon — отдельный продукт, который надо
    /// устанавливать самостоятельно. Если опрашивать его канал на машине
    /// без Sysmon, агент на каждом цикле получал бы ошибку «канал
    /// не найден» и засорял журнал. Включается, только когда Sysmon
    /// действительно установлен.
    pub sysmon: bool,
}

impl CollectorToggles {
    /// Настройки по умолчанию с учётом платформы.
    ///
    /// ПОЧЕМУ ПО ПЛАТФОРМЕ. Сборщики Linux и Windows не пересекаются:
    /// на Windows бессмысленны journald, auth.log и auditd (их нет),
    /// а на Linux нет журнала событий Windows. Если включить всё сразу,
    /// агент на каждой платформе половину времени тратил бы на попытки
    /// обратиться к несуществующим источникам.
    pub fn for_current_platform() -> Self {
        if cfg!(windows) {
            Self {
                journald: false,
                auth_log: false,
                auditd: false,
                agent: true,
                winevent: true,
                sysmon: false,
            }
        } else {
            Self {
                journald: true,
                auth_log: true,
                auditd: true,
                agent: true,
                winevent: false,
                sysmon: false,
            }
        }
    }
}

impl Default for CollectorToggles {
    fn default() -> Self {
        Self::for_current_platform()
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            core_url: "https://127.0.0.1:5050".to_string(),
            enrollment_token: String::new(),
            ca_file: String::new(),
            tls_server_name: String::new(),
            telemetry_interval_secs: 10,
            heartbeat_interval_secs: 15,
            events_interval_secs: 10,
            log_tail_lines: 200,
            max_processes: 300,
            reconnect_delay_secs: 5,
            state_dir: PathBuf::from("state"),
            allow_response_actions: false,
            collectors: CollectorToggles::default(),
            extra_log_paths: Vec::new(),
        }
    }
}

impl AgentConfig {
    /// Загружает конфигурацию из файла и переменных окружения.
    ///
    /// Явно указанный файл, который не удалось прочитать, — это ошибка:
    /// тихо игнорировать опечатку в пути опаснее, чем не запуститься.
    pub fn load(explicit_path: Option<PathBuf>) -> anyhow::Result<Self> {
        let path = explicit_path
            .or_else(|| std::env::var_os("ALYVION_AGENT_CONFIG").map(PathBuf::from))
            .or_else(default_config_path);

        let mut config = match path {
            Some(path) if path.exists() => {
                let text = std::fs::read_to_string(&path)?;
                let parsed: AgentConfig = toml::from_str(&text)?;
                tracing::info!(path = %path.display(), "конфигурация загружена из файла");
                parsed
            }
            Some(path) => {
                tracing::warn!(path = %path.display(), "файл конфигурации не найден, взяты значения по умолчанию");
                AgentConfig::default()
            }
            None => AgentConfig::default(),
        };

        config.apply_env();
        config.normalize()?;

        Ok(config)
    }

    /// Переопределение переменными окружения — удобно для запуска
    /// нескольких агентов на одной машине и для демонстрации.
    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("ALYVION_CORE_URL") {
            self.core_url = v;
        }
        if let Ok(v) = std::env::var("ALYVION_ENROLL_TOKEN") {
            self.enrollment_token = v;
        }
        if let Ok(v) = std::env::var("ALYVION_CA_FILE") {
            self.ca_file = v;
        }
        if let Ok(v) = std::env::var("ALYVION_TLS_NAME") {
            self.tls_server_name = v;
        }
        if let Ok(v) = std::env::var("ALYVION_AGENT_ID") {
            self.agent_id = v;
        }
        if let Some(v) = env_u64("ALYVION_TELEMETRY_INTERVAL") {
            self.telemetry_interval_secs = v;
        }
        if let Some(v) = env_u64("ALYVION_HEARTBEAT_INTERVAL") {
            self.heartbeat_interval_secs = v;
        }
        if let Some(v) = env_u64("ALYVION_EVENTS_INTERVAL") {
            self.events_interval_secs = v;
        }
        if let Some(v) = env_u64("ALYVION_MAX_PROCESSES") {
            self.max_processes = v as usize;
        }
        if let Some(v) = env_bool("ALYVION_ALLOW_RESPONSE") {
            self.allow_response_actions = v;
        }
        if let Ok(v) = std::env::var("ALYVION_STATE_DIR") {
            self.state_dir = PathBuf::from(v);
        }
    }

    /// Приводит конфигурацию к рабочему виду и проверяет её.
    pub fn normalize(&mut self) -> anyhow::Result<()> {
        if self.agent_id.trim().is_empty() {
            self.agent_id = hostname();
        }

        // Страховка от нулевых интервалов: иначе получим busy-loop.
        self.telemetry_interval_secs = self.telemetry_interval_secs.max(2);
        self.heartbeat_interval_secs = self.heartbeat_interval_secs.max(5);
        self.events_interval_secs = self.events_interval_secs.max(2);
        self.reconnect_delay_secs = self.reconnect_delay_secs.max(1);
        self.max_processes = self.max_processes.max(1);
        self.log_tail_lines = self.log_tail_lines.max(10);

        if !self.core_url.starts_with("http://") && !self.core_url.starts_with("https://") {
            anyhow::bail!(
                "адрес Core должен начинаться с http:// или https://, получено: {}",
                self.core_url
            );
        }

        Ok(())
    }

    pub fn identity_dir(&self) -> PathBuf {
        self.state_dir.join("mtls")
    }

    pub fn ca_path(&self) -> PathBuf {
        if self.ca_file.trim().is_empty() {
            self.identity_dir().join("ca.pem")
        } else {
            PathBuf::from(&self.ca_file)
        }
    }

    pub fn client_cert_path(&self) -> PathBuf {
        self.identity_dir().join("client.crt")
    }

    pub fn client_key_path(&self) -> PathBuf {
        self.identity_dir().join("client.key")
    }

    pub fn has_client_identity(&self) -> bool {
        self.client_cert_path().is_file() && self.client_key_path().is_file()
    }

    pub fn tls_domain(&self) -> String {
        if !self.tls_server_name.trim().is_empty() {
            return self.tls_server_name.trim().to_string();
        }
        let host = host_from_url(&self.core_url);
        if host.parse::<IpAddr>().is_ok() {
            "localhost".to_string()
        } else if host.is_empty() {
            "alyvion-core".to_string()
        } else {
            host
        }
    }

    pub fn events_interval(&self) -> Duration {
        Duration::from_secs(self.events_interval_secs)
    }

    pub fn reconnect_delay(&self) -> Duration {
        Duration::from_secs(self.reconnect_delay_secs)
    }

    /// Список действий реагирования, которые агент готов выполнять.
    ///
    /// Если реагирование выключено, список пуст — Core это увидит
    /// и не будет присылать команды, которые всё равно будут отклонены.
    /// Возможности реагирования, объявляемые Core.
    ///
    /// Все перечисленные действия реализованы И НА LINUX, И НА WINDOWS:
    /// на Linux через `iptables`, `kill` и `usermod`, на Windows через
    /// `netsh advfirewall`, `taskkill` и `net user`. Поэтому список
    /// не зависит от платформы — общий набор соответствует реальным
    /// возможностям агента на любой из них.
    ///
    /// ВАЖНО: список объявляется, только если реагирование разрешено
    /// конфигурацией. Панель Core показывает по нему доступные кнопки,
    /// поэтому объявление невыполнимого действия было бы обманом
    /// оператора.
    pub fn declared_capabilities(&self) -> Vec<i32> {
        if !self.allow_response_actions {
            return Vec::new();
        }

        use crate::pb::ResponseActionType as A;
        [
            A::BlockIp,
            A::UnblockIp,
            A::KillProcess,
            A::DisableUser,
            A::EnableUser,
            A::IsolateHost,
            A::ReleaseHost,
            A::CollectForensics,
            A::QuarantineFile,
            A::PingAction,
        ]
        .into_iter()
        .map(|a| a as i32)
        .collect()
    }

    /// Имена активных источников событий — уходят в Core для отображения.
    ///
    /// Словарь имён согласован с описанием поля `source` в контракте:
    /// `journald | auth.log | auditd | wineventlog | sysmon | agent`.
    /// Core показывает эти имена оператору, поэтому они должны совпадать
    /// с тем, что агент действительно собирает.
    pub fn active_collectors(&self) -> Vec<String> {
        let mut list = Vec::new();

        if self.collectors.journald {
            list.push("journald".to_string());
        }
        if self.collectors.auth_log {
            list.push("auth.log".to_string());
        }
        if self.collectors.auditd {
            list.push("auditd".to_string());
        }
        if self.collectors.winevent {
            list.push("wineventlog".to_string());
        }
        if self.collectors.sysmon {
            list.push("sysmon".to_string());
        }
        if self.collectors.agent {
            list.push("agent".to_string());
        }

        list
    }
}

fn default_config_path() -> Option<PathBuf> {
    let local = PathBuf::from("alyvion-agent.toml");
    local.exists().then_some(local)
}

fn host_from_url(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split('/').next().unwrap_or(rest);
    let host = match hostport.rsplit_once('@') {
        Some((_, h)) => h,
        None => hostport,
    };
    host.split('%').next().unwrap_or(host)
        .split(']')
        .next()
        .unwrap_or(host)
        .trim_start_matches('[')
        .split(':')
        .next()
        .unwrap_or(host)
        .to_string()
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.trim().parse().ok()
}

fn env_bool(name: &str) -> Option<bool> {
    match std::env::var(name).ok()?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Имя узла. Используется как agent_id, если он не задан явно.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| sysinfo::System::host_name())
        .unwrap_or_else(|| "unknown-host".to_string())
}

/// Сетевые адреса узла.
///
/// Основной путь — чтение таблицы локальных адресов ядра `/proc/net/fib_trie`:
/// это надёжнее разрешения имени хоста и не зависит от внешних утилит.
/// Резервный путь — определить адрес, через который узел видит сеть,
/// подключив UDP-сокет (пакеты при этом не отправляются).
pub fn local_ip_addresses() -> Vec<String> {
    let mut addresses = addresses_from_fib_trie();

    if addresses.is_empty() {
        if let Some(addr) = primary_interface_address() {
            addresses.push(addr);
        }
    }

    addresses.sort();
    addresses.dedup();
    addresses
}

/// Разбирает `/proc/net/fib_trie` и возвращает локальные адреса узла.
///
/// Формат: адрес идёт строкой `|-- <ip>`, а признак принадлежности узлу —
/// следующей строкой `/NN host LOCAL`. Служебные адреса (петля,
/// широковещательные, link-local) для отчёта в Core бесполезны.
fn addresses_from_fib_trie() -> Vec<String> {
    let Ok(content) = std::fs::read_to_string("/proc/net/fib_trie") else {
        return Vec::new();
    };

    let mut addresses = Vec::new();
    let mut candidate: Option<IpAddr> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("|-- ") {
            candidate = rest.trim().parse::<IpAddr>().ok();
        } else if trimmed.contains("host LOCAL") {
            if let Some(ip) = candidate.take() {
                if is_reportable(ip) {
                    addresses.push(ip.to_string());
                }
            }
        }
    }

    addresses
}

/// Определяет адрес основного сетевого интерфейса.
///
/// Приём «подключить UDP-сокет»: ядро выбирает исходящий интерфейс
/// и назначает локальный адрес, но ни одного пакета в сеть не уходит.
fn primary_interface_address() -> Option<String> {
    use std::net::UdpSocket;

    // Адрес назначения может быть любым маршрутизируемым: важен лишь
    // выбор интерфейса, соединение не устанавливается.
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;

    let addr = socket.local_addr().ok()?;
    is_reportable(addr.ip()).then(|| addr.ip().to_string())
}

/// Отбрасывает адреса, не несущие смысла в отчёте об узле.
fn is_reportable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_link_local()
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn пустой_agent_id_заменяется_именем_хоста() {
        let mut config = AgentConfig::default();
        config.normalize().expect("нормализация должна пройти");
        assert!(!config.agent_id.is_empty());
    }

    #[test]
    fn нулевые_интервалы_поднимаются_до_минимума() {
        let mut config = AgentConfig {
            telemetry_interval_secs: 0,
            heartbeat_interval_secs: 0,
            ..Default::default()
        };
        config.normalize().unwrap();
        assert!(config.telemetry_interval_secs >= 2);
        assert!(config.heartbeat_interval_secs >= 5);
    }

    #[test]
    fn неверная_схема_адреса_отклоняется() {
        let mut config = AgentConfig {
            core_url: "127.0.0.1:5050".to_string(),
            ..Default::default()
        };
        assert!(config.normalize().is_err());
    }

    #[test]
    fn при_выключенном_реагировании_возможностей_нет() {
        let config = AgentConfig {
            allow_response_actions: false,
            ..Default::default()
        };
        assert!(config.declared_capabilities().is_empty());
    }

    #[test]
    fn при_включённом_реагировании_возможности_объявляются() {
        let config = AgentConfig {
            allow_response_actions: true,
            ..Default::default()
        };
        assert!(!config.declared_capabilities().is_empty());
    }
}
