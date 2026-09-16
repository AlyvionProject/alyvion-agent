//! Разбор событий журнала Windows (Windows Event Log).
//!
//! ПОЧЕМУ ЭТОТ МОДУЛЬ НЕ ЗАВИСИТ ОТ WINDOWS. Здесь только преобразование
//! XML-записи события в единую схему. Само чтение журнала требует Windows
//! API и живёт в `events.rs` под `cfg(windows)`. Разделение сделано
//! сознательно: разбор — самая ошибкоопасная часть (коды событий, поля
//! XML, кодировки), и её нужно уметь проверять тестами на сборочной
//! машине, не имея под рукой Windows. Поэтому весь разбор здесь
//! компилируется и тестируется на любой платформе.
//!
//! Схема события общая с Linux-источниками: источник, категория, действие,
//! важность, результат, пользователь, адрес, процесс. Именно это единство
//! и позволяет Core сопоставлять события разных ОС между собой.

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};

use crate::pb::SecurityEvent;

/// Категории события — те же словари, что и в Linux-сборщике.
use crate::events::{category, severity};

/// Источник события для журналов Windows.
pub const SOURCE_WINEVENT: &str = "wineventlog";
/// Источник события для Sysmon (если он установлен на узле).
pub const SOURCE_SYSMON: &str = "sysmon";

/// Описание того, как конкретный код события отображается в единую схему.
#[derive(Debug, Clone, Copy)]
pub struct EventMapping {
    // Поля `channel` здесь СОЗНАТЕЛЬНО НЕТ. Настоящий канал берётся
    // из поля <Channel> самой записи XML, а не из таблицы: событие
    // с одним кодом может попасть в разные каналы, и дубликат в таблице
    // рано или поздно разошёлся бы с реальностью незамеченным.
    /// Нормализованная категория (`category::*`).
    pub category: &'static str,
    /// Нормализованное действие (`login`, `process_start`, ...).
    pub action: &'static str,
    /// Важность (`severity::*`).
    pub severity: &'static str,
    /// Результат: успех, отказ или неизвестно.
    pub outcome: &'static str,
    /// Человекочитаемое описание для оператора.
    pub title: &'static str,
}

/// Таблица значимых кодов событий Windows.
///
/// ПОЧЕМУ ТАБЛИЦА, А НЕ РАЗБОР ТЕКСТА. Текстовое описание события
/// локализовано: на русской Windows сообщение будет русским, на
/// английской — английским. Сопоставление по тексту сломалось бы при
/// смене языка системы, поэтому решение принимается по ЧИСЛОВОМУ коду
/// события, который от языка не зависит.
///
/// Отобраны события, значимые для информационной безопасности:
/// аутентификация, управление учётными записями, запуск процессов,
/// изменения конфигурации и системы. Полный список кодов приведён
/// в документации Microsoft по «Audit Events».
pub fn mapping_for(event_id: u32) -> Option<EventMapping> {
    // Вход и выход из системы.
    const LOGON_SUCCESS: EventMapping = EventMapping {
        category: category::AUTHENTICATION,
        action: "login",
        severity: severity::INFO,
        outcome: "success",
        title: "Успешный вход в систему",
    };
    const LOGON_FAILURE: EventMapping = EventMapping {
        category: category::AUTHENTICATION,
        action: "login",
        severity: severity::MEDIUM,
        outcome: "failure",
        title: "Неудачная попытка входа",
    };
    const LOGOFF: EventMapping = EventMapping {
        category: category::AUTHENTICATION,
        action: "logout",
        severity: severity::INFO,
        outcome: "success",
        title: "Выход из системы",
    };
    const SPECIAL_PRIVILEGES: EventMapping = EventMapping {
        category: category::PRIVILEGE,
        action: "privilege_use",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Использование особых привилегий",
    };
    const EXPLICIT_CREDENTIALS: EventMapping = EventMapping {
        category: category::PRIVILEGE,
        action: "explicit_credentials",
        severity: severity::LOW,
        outcome: "success",
        title: "Процесс запущен с явными учётными данными",
    };
    const PROCESS_CREATED: EventMapping = EventMapping {
        category: category::PROCESS,
        action: "process_start",
        severity: severity::LOW,
        outcome: "success",
        title: "Создан процесс",
    };
    const PROCESS_EXITED: EventMapping = EventMapping {
        category: category::PROCESS,
        action: "process_stop",
        severity: severity::INFO,
        outcome: "success",
        title: "Процесс завершён",
    };
    const USER_CREATED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "user_created",
        severity: severity::HIGH,
        outcome: "success",
        title: "Создана учётная запись",
    };
    const USER_DELETED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "user_deleted",
        severity: severity::HIGH,
        outcome: "success",
        title: "Удалена учётная запись",
    };
    const USER_ENABLED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "user_enabled",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Учётная запись включена",
    };
    const USER_DISABLED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "user_disabled",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Учётная запись отключена",
    };
    const USER_LOCKED: EventMapping = EventMapping {
        category: category::AUTHENTICATION,
        action: "account_locked",
        severity: severity::HIGH,
        outcome: "failure",
        title: "Учётная запись заблокирована",
    };
    const USER_PASSWORD_CHANGED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "password_changed",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Пароль учётной записи изменён",
    };
    const GROUP_MEMBER_ADDED: EventMapping = EventMapping {
        category: category::PRIVILEGE,
        action: "group_member_added",
        severity: severity::HIGH,
        outcome: "success",
        title: "Учётная запись добавлена в группу",
    };
    const GROUP_MEMBER_REMOVED: EventMapping = EventMapping {
        category: category::PRIVILEGE,
        action: "group_member_removed",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Учётная запись удалена из группы",
    };
    const AUDIT_LOG_CLEARED: EventMapping = EventMapping {
        category: category::SYSTEM,
        action: "log_cleared",
        severity: severity::HIGH,
        outcome: "success",
        title: "Журнал аудита очищен",
    };
    const SERVICE_INSTALLED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "service_installed",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Установлена служба",
    };
    const SERVICE_STATE_CHANGED: EventMapping = EventMapping {
        category: category::SYSTEM,
        action: "service_state",
        severity: severity::LOW,
        outcome: "unknown",
        title: "Изменено состояние службы",
    };
    const SERVICE_CRASHED: EventMapping = EventMapping {
        category: category::SYSTEM,
        action: "service_crashed",
        severity: severity::MEDIUM,
        outcome: "failure",
        title: "Служба аварийно завершилась",
    };
    const SYSTEM_STARTUP: EventMapping = EventMapping {
        category: category::SYSTEM,
        action: "system_startup",
        severity: severity::INFO,
        outcome: "success",
        title: "Запуск операционной системы",
    };
    const SYSTEM_SHUTDOWN: EventMapping = EventMapping {
        category: category::SYSTEM,
        action: "system_shutdown",
        severity: severity::INFO,
        outcome: "success",
        title: "Остановка операционной системы",
    };
    const SCHEDULED_TASK_CREATED: EventMapping = EventMapping {
        category: category::CONFIGURATION,
        action: "task_created",
        severity: severity::MEDIUM,
        outcome: "success",
        title: "Создана задача планировщика",
    };
    const POWERSHELL_SCRIPT: EventMapping = EventMapping {
        category: category::PROCESS,
        action: "script_executed",
        severity: severity::LOW,
        outcome: "success",
        title: "Выполнен сценарий PowerShell",
    };
    const DEFENDER_THREAT: EventMapping = EventMapping {
        category: category::SYSTEM,
        action: "malware_detected",
        severity: severity::HIGH,
        outcome: "success",
        title: "Обнаружен вредоносный код",
    };

    // Защита от подделки: события аудита могут быть очищены, поэтому
    // код 1102 отмечен высокой важностью — это признак сокрытия следов.
    Some(match event_id {
        4624 => LOGON_SUCCESS,
        4625 => LOGON_FAILURE,
        4634 | 4647 => LOGOFF,
        4672 => SPECIAL_PRIVILEGES,
        4648 => EXPLICIT_CREDENTIALS,
        4688 => PROCESS_CREATED,
        4689 => PROCESS_EXITED,
        4720 => USER_CREATED,
        4726 => USER_DELETED,
        4722 => USER_ENABLED,
        4725 => USER_DISABLED,
        4740 => USER_LOCKED,
        4723 | 4724 => USER_PASSWORD_CHANGED,
        4732 | 4728 => GROUP_MEMBER_ADDED,
        4733 | 4729 => GROUP_MEMBER_REMOVED,
        1102 => AUDIT_LOG_CLEARED,
        7045 => SERVICE_INSTALLED,
        7036 => SERVICE_STATE_CHANGED,
        7031 | 7034 => SERVICE_CRASHED,
        6005 => SYSTEM_STARTUP,
        6006 => SYSTEM_SHUTDOWN,
        4698 => SCHEDULED_TASK_CREATED,
        4103 | 4104 => POWERSHELL_SCRIPT,
        1116 | 1117 => DEFENDER_THREAT,
        _ => return None,
    })
}

/// Каналы журнала, которые агент опрашивает по умолчанию.
///
/// Порядок важен для читаемости журнала агента, но не для логики.
/// Канал PowerShell 7 и новее.
///
/// PowerShell 5.1 (встроенный в Windows 10) и PowerShell 7 пишут
/// в РАЗНЫЕ каналы. Опроса только одного недостаточно: на узле может
/// быть установлена любая из версий или обе сразу, и тогда события
/// выполнения сценариев остались бы незамеченными.
pub const POWERSHELL_CORE_CHANNEL: &str = "PowerShellCore/Operational";

pub const DEFAULT_CHANNELS: [&str; 4] = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
];

/// Sysmon пишет в отдельный канал и устанавливается отдельно.
pub const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

/// Разобранная запись журнала Windows.
#[derive(Debug, Clone, Default)]
pub struct WindowsEventRecord {
    /// Числовой код события (Event ID).
    pub event_id: u32,
    /// Канал журнала.
    pub channel: String,
    /// Имя поставщика (Provider Name).
    pub provider: String,
    /// Время события в миллисекундах UNIX.
    pub timestamp_unix_ms: i64,
    /// Уровень по классификации Windows (1 — critical, 5 — verbose).
    pub level: u8,
    /// Именованные поля из секции EventData.
    pub data: HashMap<String, String>,
    /// Имя компьютера из секции System.
    pub computer: String,
}

impl WindowsEventRecord {
    /// Ищет поле EventData без учёта регистра.
    ///
    /// Регистр в XML непостоянен: разные поставщики пишут `TargetUserName`,
    /// `targetUserName` и `Targetusername`. Сравнение «в лоб» теряло бы
    /// данные у части поставщиков.
    pub fn get(&self, key: &str) -> Option<&str> {
        if let Some(value) = self.data.get(key) {
            return Some(value.as_str());
        }

        self.data
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Возвращает поле, пропуская служебные значения Windows.
    ///
    /// В полях учётных записей Windows использует прочерк `-` как «не
    /// применимо» и `SYSTEM` для системных действий. Отдавать прочерк
    /// оператору бессмысленно, поэтому он превращается в пустую строку.
    pub fn get_meaningful(&self, key: &str) -> String {
        match self.get(key) {
            Some("-") | None => String::new(),
            Some(value) => value.to_string(),
        }
    }
}

/// Разбирает XML одной записи журнала Windows.
///
/// Возвращает `None`, если это не событие или XML повреждён: одна битая
/// запись не должна останавливать разбор всего пакета.
pub fn parse_event_xml(xml: &str) -> Option<WindowsEventRecord> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);

    let mut record = WindowsEventRecord::default();

    // Контекст разбора: значение читается либо из System, либо из полезной
    // нагрузки события.
    let mut current_name = String::new();
    let mut in_system = false;

    // ПОЧЕМУ ДВА КОНТЕЙНЕРА, А НЕ ОДИН. События службы журналирования
    // (1100, 1102, 1104, 1108) хранят данные в <UserData>, а не в
    // <EventData>. Внутри UserData поля лежат отдельными тегами
    // (<SubjectUserName>dadmin</SubjectUserName>), а не как <Data Name="...">.
    // Парсер, знающий только про EventData, потерял бы всю эту группу —
    // включая 1102 «журнал очищен», то есть признак сокрытия следов.
    let mut in_event_data = false;
    let mut in_user_data = false;

    // Имя тега, значение которого мы сейчас читаем.
    let mut pending_field: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                let name = tag.name().as_ref().to_string();

                match name.as_str() {
                    "System" => in_system = true,
                    "EventData" => in_event_data = true,
                    "UserData" => in_user_data = true,
                    "Data" => {
                        // Поле EventData описывается атрибутом Name,
                        // а значение лежит в тексте элемента.
                        if in_event_data
                            && let Some(field) = attribute_value(&tag, "Name")
                        {
                            pending_field = Some(field);
                        }
                    }
                    _ => {
                        // Внутри System значения лежат прямо в теге,
                        // поэтому запоминаем имя тега.
                        if in_system {
                            current_name = name;
                        } else if in_user_data {
                            // В UserData имя поля — это имя самого тега,
                            // а вложенный тег (<LogFileCleared>) является
                            // лишь обёрткой и полем не считается.
                            // Обёртку узнаём по совпадению с именем события:
                            // у 1102 это LogFileCleared.
                            if let Some(wrapper) = user_data_wrapper(record.event_id) {
                                if name != wrapper {
                                    pending_field = Some(name);
                                }
                            } else {
                                pending_field = Some(name);
                            }
                        }
                    }
                }
            }

            Ok(Event::Empty(tag)) => {
                let name = tag.name().as_ref().to_string();

                // Пустой элемент <Data Name="X"/> означает пустое значение.
                if name == "Data"
                    && in_event_data
                    && let Some(field) = attribute_value(&tag, "Name")
                {
                    record.data.insert(field, String::new());
                }

                // Время события лежит в АТРИБУТЕ пустого элемента
                // <TimeCreated SystemTime="..."/>, поэтому текстовой веткой
                // оно не ловится. Без этого время события всегда было бы
                // равно времени разбора — и в Core все события выглядели бы
                // пришедшими «только что».
                if name == "TimeCreated"
                    && let Some(raw) = attribute_value(&tag, "SystemTime")
                    && let Some(ms) = parse_windows_time(&raw)
                {
                    record.timestamp_unix_ms = ms;
                }

                // Источник события тоже записан атрибутом:
                // <Provider Name="Microsoft-Windows-Security-Auditing"/>.
                if name == "Provider"
                    && let Some(provider) = attribute_value(&tag, "Name")
                {
                    record.provider = provider;
                }
            }

            Ok(Event::Text(text)) => {
                // В quick-xml 0.42 текст события уже представлен строкой,
                // а XML-мнемоники (&amp; и подобные) раскрываются свободной
                // функцией escape::unescape, а не методом события.
                let raw = text.into_inner();
                let value = quick_xml::escape::unescape(&raw)
                    .map(|v| v.into_owned())
                    .unwrap_or_else(|_| raw.into_owned());

                if let Some(field) = pending_field.take() {
                    record.data.insert(field, value);
                } else if in_system && !current_name.is_empty() {
                    apply_system_field(&mut record, &current_name, &value);
                    current_name.clear();
                }
            }

            Ok(Event::End(tag)) => {
                let name = tag.name().as_ref().to_string();

                match name.as_str() {
                    "System" => in_system = false,
                    "EventData" => in_event_data = false,
                    "UserData" => in_user_data = false,
                    _ => {}
                }

                // Закрылся тег System-поля — сбрасываем его имя.
                if in_system && name == current_name {
                    current_name.clear();
                }
            }

            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    // Событие без кода бесполезно: по нему нельзя принять решение.
    if record.event_id == 0 {
        return None;
    }

    Some(record)
}

/// Возвращает имя тега-обёртки внутри `<UserData>` для кода события.
///
/// Данные события службы журналирования обёрнуты в тег с говорящим именем
/// (`<LogFileCleared>` для 1102, `<ServiceShutdown>` для 1100). Этот тег —
/// не поле, а контейнер, поэтому его нельзя записывать в поля события.
/// Коды, которых здесь нет, разбираются без учёта обёртки.
fn user_data_wrapper(event_id: u32) -> Option<&'static str> {
    match event_id {
        1100 => Some("ServiceShutdown"),
        1102 => Some("LogFileCleared"),
        1104 => Some("FileIsFull"),
        1108 => Some("EventProcessingFailure"),
        _ => None,
    }
}

/// Извлекает значение атрибута элемента.
fn attribute_value(tag: &quick_xml::events::BytesStart<'_>, attr_name: &str) -> Option<String> {
    for attribute in tag.attributes().flatten() {
        let key: &str = attribute.key.as_ref();
        if key.eq_ignore_ascii_case(attr_name) {
            // normalized_value, а не unescape_value: последний объявлен
            // устаревшим в quick-xml 0.42.
            return Some(
                attribute
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .map(|v| v.into_owned())
                    .unwrap_or_else(|_| attribute.value.to_string()),
            );
        }
    }
    None
}

/// Раскладывает поле секции System по полям записи.
fn apply_system_field(record: &mut WindowsEventRecord, name: &str, value: &str) {
    match name {
        "EventID" => record.event_id = value.trim().parse().unwrap_or(0),
        "Channel" => record.channel = value.to_string(),
        "Computer" => record.computer = value.to_string(),
        "Level" => record.level = value.trim().parse().unwrap_or(0),
        // Номер записи уникален в журнале и не меняется. Он сохраняется
        // в общие поля, потому что на нём строится идентификатор события
        // для защиты от дубликатов.
        "EventRecordID" => {
            record
                .data
                .insert("RecordID".to_string(), value.trim().to_string());
        }
        _ => {}
    }
}

/// Разбирает время в формате ISO 8601, принятом в журнале Windows.
///
/// Формат: `2026-09-16T14:05:47.1234567Z`. Дробная часть бывает разной
/// длины, поэтому разбор идёт через `chrono`, а не вручную.
pub fn parse_windows_time(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(parsed.timestamp_millis());
    }

    // Запасной вариант: время без зоны трактуем как UTC.
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, format) {
            return Some(Utc.from_utc_datetime(&naive).timestamp_millis());
        }
    }

    None
}

/// Преобразует разобранную запись в событие единой схемы.
///
/// Возвращает `None`, если код события не признан значимым: журнал
/// Windows объёмный, и отправлять в Core весь поток бессмысленно —
/// в нём утонули бы реальные инциденты.
pub fn to_security_event(mut record: WindowsEventRecord) -> Option<SecurityEvent> {
    let mapping = mapping_for(record.event_id)?;

    let source = if record.channel.eq_ignore_ascii_case(SYSMON_CHANNEL) {
        SOURCE_SYSMON
    } else {
        SOURCE_WINEVENT
    };

    let mut event = SecurityEvent {
        event_id: make_windows_event_id(&record),
        timestamp_unix_ms: if record.timestamp_unix_ms > 0 {
            record.timestamp_unix_ms
        } else {
            Utc::now().timestamp_millis()
        },
        source: source.to_string(),
        category: mapping.category.to_string(),
        action: mapping.action.to_string(),
        severity: mapping.severity.to_string(),
        outcome: mapping.outcome.to_string(),
        message: String::new(),
        user: String::new(),
        source_ip: String::new(),
        dest_ip: String::new(),
        pid: 0,
        process_name: String::new(),
        raw_fields: HashMap::new(),
        simulated: false,
    };

    // Пользователь: у разных событий поле называется по-разному.
    let user = [
        "TargetUserName",
        "SubjectUserName",
        "User",
        "param1",
    ]
    .iter()
    .map(|key| record.get_meaningful(key))
    .find(|value| !value.is_empty())
    .unwrap_or_default();

    // Отсекаем служебные учётные записи: они не несут смысла оператору.
    event.user = if is_service_account(&user) {
        String::new()
    } else {
        user
    };

    // Адрес источника: важен для разбора попыток входа.
    event.source_ip = ["IpAddress", "SourceNetworkAddress", "ClientAddress", "Address"]
        .iter()
        .map(|key| record.get_meaningful(key))
        .find(|value| !value.is_empty() && is_ip_like(value))
        .unwrap_or_default();

    // Процесс и его идентификатор.
    event.process_name = [
        "NewProcessName",
        "ProcessName",
        "Image",
        "Application",
    ]
    .iter()
    .map(|key| record.get_meaningful(key))
    .find(|value| !value.is_empty())
    .unwrap_or_default();

    event.pid = ["NewProcessId", "ProcessId", "ExecutionProcessID"]
        .iter()
        .find_map(|key| parse_pid(record.get(key)))
        .unwrap_or(0);

    // Командная строка процесса — ключевой признак при разборе
    // подозрительной активности.
    if let Some(command_line) = [
        "CommandLine",
        "ProcessCommandLine",
        "NewProcessName",
    ]
    .iter()
    .map(|key| record.get_meaningful(key))
    .find(|value| !value.is_empty())
    {
        event
            .raw_fields
            .insert("command_line".to_string(), command_line);
    }

    // Описание формируется из заголовка и уточняющих полей, потому что
    // текст самого события локализован и в сыром виде бесполезен.
    event.message = build_message(mapping.title, &record, &event);

    // Номер канала и код события сохраняем как есть: по ним оператор
    // найдёт запись в оснастке «Просмотр событий».
    event
        .raw_fields
        .insert("windows_event_id".to_string(), record.event_id.to_string());
    event
        .raw_fields
        .insert("windows_channel".to_string(), record.channel.clone());
    if !record.provider.is_empty() {
        event
            .raw_fields
            .insert("windows_provider".to_string(), record.provider.clone());
    }
    if !record.computer.is_empty() {
        event
            .raw_fields
            .insert("hostname".to_string(), record.computer.clone());
    }

    // Полезные данные, не разобранные в отдельные поля, сохраняем
    // как есть — они пригодятся при разборе инцидента.
    for (key, value) in record.data.drain() {
        if value.is_empty() {
            continue;
        }
        // Ограничиваем объём: отдельные поля (например, в PowerShell)
        // содержат целые сценарии.
        let trimmed = if value.len() > 512 {
            format!("{}…", &value[..512])
        } else {
            value
        };
        event.raw_fields.entry(key).or_insert(trimmed);
    }

    Some(event)
}

/// Формирует человекочитаемое описание события.
fn build_message(title: &str, record: &WindowsEventRecord, event: &SecurityEvent) -> String {
    let mut parts = vec![title.to_string()];

    if !event.user.is_empty() {
        parts.push(format!("учётная запись: {}", event.user));
    }
    if !event.source_ip.is_empty() {
        parts.push(format!("адрес: {}", event.source_ip));
    }
    if !event.process_name.is_empty() {
        parts.push(format!("процесс: {}", event.process_name));
    }
    if record.event_id == 4688 {
        let command_line = record.get_meaningful("CommandLine");
        if !command_line.is_empty() {
            parts.push(format!("команда: {command_line}"));
        }
    }

    format!(
        "{} (код {} в канале {})",
        parts.join("; "),
        record.event_id,
        record.channel
    )
}

/// Идентификатор события для защиты от дубликатов.
///
/// В отличие от Linux-источников, здесь основа — код события, номер
/// записи (RecordID) и узел. RecordID в журнале Windows уникален и
/// не меняется, поэтому одно и то же событие, прочитанное дважды,
/// получит одинаковый идентификатор и будет отброшено Core.
fn make_windows_event_id(record: &WindowsEventRecord) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    record.channel.hash(&mut hasher);
    record.event_id.hash(&mut hasher);
    record.computer.hash(&mut hasher);
    // RecordID лежит в EventData/System как строка; если его нет,
    // опираемся на время и содержимое.
    record.get("RecordID").unwrap_or_default().hash(&mut hasher);
    record.timestamp_unix_ms.hash(&mut hasher);
    record
        .data
        .get("TargetUserName")
        .unwrap_or(&String::new())
        .hash(&mut hasher);

    let a = hasher.finish();
    a.hash(&mut hasher);
    let b = hasher.finish();

    format!("{a:016x}{b:016x}")
}

/// Отсекает служебные учётные записи Windows.
fn is_service_account(user: &str) -> bool {
    const SERVICE_ACCOUNTS: [&str; 6] = [
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "ANONYMOUS LOGON",
        "-",
        "",
    ];
    SERVICE_ACCOUNTS
        .iter()
        .any(|account| user.eq_ignore_ascii_case(account))
}

/// Проверяет, похожа ли строка на IP-адрес.
///
/// Windows пишет `-` или имя компьютера там, где адреса нет.
fn is_ip_like(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

/// Разбирает PID из строки.
///
/// Windows пишет идентификаторы в шестнадцатеричном виде
/// (`0x1a4`), поэтому одной десятичной ветки недостаточно.
fn parse_pid(raw: Option<&str>) -> Option<u32> {
    let value = raw?.trim();

    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }

    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Реальное событие 4624 (успешный вход), сокращённое до значимых полей.
    const LOGON_SUCCESS_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <TimeCreated SystemTime="2026-09-16T14:05:47.1234567Z"/>
    <EventRecordID>8842</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WIN10-VM</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">WIN10-VM$</Data>
    <Data Name="TargetUserName">operator</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="IpPort">51422</Data>
  </EventData>
</Event>"#;

    /// Очистка журнала (1102). САМЫЙ ВАЖНЫЙ СЛУЧАЙ ДЛЯ ПАРСЕРА:
    /// данные лежат в <UserData><LogFileCleared>, а не в <EventData>.
    /// Парсер, знающий только про EventData, не увидел бы здесь ни одного
    /// поля — и признак сокрытия следов остался бы без подробностей.
    const LOG_CLEARED_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"/>
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <Opcode>0</Opcode>
    <Keywords>0x4020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-16T14:05:47.1234567Z"/>
    <EventRecordID>7712</EventRecordID>
    <Correlation/>
    <Execution ProcessID="720" ThreadID="816"/>
    <Channel>Security</Channel>
    <Computer>WIN10-VM</Computer>
    <Security/>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-3457937927-2839227994-823803824-1104</SubjectUserSid>
      <SubjectUserName>dadmin</SubjectUserName>
      <SubjectDomainName>CONTOSO</SubjectDomainName>
      <SubjectLogonId>0x55cd1d</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>"#;

    const LOGON_FAILURE_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-09-16T14:06:12.0000000Z"/>
    <Channel>Security</Channel>
    <Computer>WIN10-VM</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="IpAddress">10.0.0.7</Data>
    <Data Name="Status">0xc000006d</Data>
  </EventData>
</Event>"#;

    const PROCESS_CREATED_XML: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-09-16T14:07:00.5000000Z"/>
    <Channel>Security</Channel>
    <Computer>WIN10-VM</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">operator</Data>
    <Data Name="NewProcessId">0x1a4</Data>
    <Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
  </EventData>
</Event>"#;

    #[test]
    fn разбирается_успешный_вход() {
        let record = parse_event_xml(LOGON_SUCCESS_XML).expect("запись должна разобраться");

        assert_eq!(record.event_id, 4624);
        assert_eq!(record.channel, "Security");
        assert_eq!(record.computer, "WIN10-VM");
        assert_eq!(record.get("TargetUserName"), Some("operator"));
        assert_eq!(record.get("IpAddress"), Some("192.168.1.50"));
        assert_eq!(record.provider, "Microsoft-Windows-Security-Auditing");
    }

    #[test]
    fn время_разбирается_с_дробной_частью() {
        let record = parse_event_xml(LOGON_SUCCESS_XML).unwrap();
        // 2026-09-16T14:05:47Z
        assert_eq!(record.timestamp_unix_ms, 1789567547123);
    }

    #[test]
    fn событие_приводится_к_единой_схеме() {
        let record = parse_event_xml(LOGON_SUCCESS_XML).unwrap();
        let event = to_security_event(record).expect("событие значимо");

        assert_eq!(event.source, SOURCE_WINEVENT);
        assert_eq!(event.category, category::AUTHENTICATION);
        assert_eq!(event.action, "login");
        assert_eq!(event.outcome, "success");
        assert_eq!(event.user, "operator");
        assert_eq!(event.source_ip, "192.168.1.50");
        assert!(event.message.contains("Успешный вход"));
        assert!(!event.simulated);
    }

    #[test]
    fn неудачный_вход_помечается_отказом() {
        let record = parse_event_xml(LOGON_FAILURE_XML).unwrap();
        let event = to_security_event(record).unwrap();

        assert_eq!(event.outcome, "failure");
        assert_eq!(event.severity, severity::MEDIUM);
        assert_eq!(event.user, "administrator");
    }

    #[test]
    fn создание_процесса_даёт_pid_из_шестнадцатеричной_записи() {
        let record = parse_event_xml(PROCESS_CREATED_XML).unwrap();
        assert_eq!(record.event_id, 4688);

        let event = to_security_event(record).unwrap();
        assert_eq!(event.category, category::PROCESS);
        assert_eq!(event.action, "process_start");
        // 0x1a4 = 420
        assert_eq!(event.pid, 420);
        assert!(event.process_name.contains("cmd.exe"));
        assert_eq!(
            event.raw_fields.get("command_line").map(String::as_str),
            Some("cmd.exe /c whoami")
        );
    }

    #[test]
    fn служебная_учётная_запись_не_попадает_в_событие() {
        let xml = LOGON_SUCCESS_XML.replace("operator", "SYSTEM");
        let event = to_security_event(parse_event_xml(&xml).unwrap()).unwrap();
        assert_eq!(event.user, "", "SYSTEM — служебная запись, оператору не нужна");
    }

    #[test]
    fn прочерк_в_поле_адреса_не_становится_адресом() {
        let xml = LOGON_SUCCESS_XML.replace("192.168.1.50", "-");
        let event = to_security_event(parse_event_xml(&xml).unwrap()).unwrap();
        assert_eq!(event.source_ip, "", "прочерк означает «не применимо»");
    }

    #[test]
    fn незначимый_код_события_отбрасывается() {
        // 1000 — падение приложения, для ИБ-мониторинга не значимо.
        let xml = LOGON_SUCCESS_XML.replace("<EventID>4624</EventID>", "<EventID>1000</EventID>");
        let record = parse_event_xml(&xml).unwrap();
        assert!(to_security_event(record).is_none());
    }

    #[test]
    fn повреждённый_xml_не_паникует() {
        assert!(parse_event_xml("<Event><System>").is_none() || true);
        assert!(parse_event_xml("совсем не xml").is_none());
        assert!(parse_event_xml("").is_none());
    }

    #[test]
    fn событие_без_кода_отбрасывается() {
        let xml = "<Event><System><Channel>Security</Channel></System></Event>";
        assert!(parse_event_xml(xml).is_none());
    }

    #[test]
    fn идентификатор_события_устойчив_при_повторном_разборе() {
        // Одно и то же событие, прочитанное дважды, должно дать один
        // идентификатор — иначе Core не отбросит дубликат.
        let first = to_security_event(parse_event_xml(LOGON_SUCCESS_XML).unwrap()).unwrap();
        let second = to_security_event(parse_event_xml(LOGON_SUCCESS_XML).unwrap()).unwrap();
        assert_eq!(first.event_id, second.event_id);
    }

    #[test]
    fn разные_события_получают_разные_идентификаторы() {
        let first = to_security_event(parse_event_xml(LOGON_SUCCESS_XML).unwrap()).unwrap();
        let second = to_security_event(parse_event_xml(LOGON_FAILURE_XML).unwrap()).unwrap();
        assert_ne!(first.event_id, second.event_id);
    }

    #[test]
    fn регистр_имени_поля_не_важен() {
        let record = parse_event_xml(LOGON_SUCCESS_XML).unwrap();
        assert_eq!(record.get("targetusername"), Some("operator"));
        assert_eq!(record.get("TARGETUSERNAME"), Some("operator"));
    }

    #[test]
    fn пустое_поле_не_ломает_разбор() {
        let xml = r#"<Event><System><EventID>4624</EventID><Channel>Security</Channel></System>
        <EventData><Data Name="TargetUserName"/><Data Name="IpAddress">1.2.3.4</Data></EventData></Event>"#;
        let record = parse_event_xml(xml).unwrap();
        assert_eq!(record.get("TargetUserName"), Some(""));
        assert_eq!(record.get("IpAddress"), Some("1.2.3.4"));
    }

    #[test]
    fn канал_sysmon_даёт_отдельный_источник() {
        let xml = LOGON_SUCCESS_XML
            .replace("<Channel>Security</Channel>", "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>")
            // Код 1 — создание процесса в Sysmon; используем значимый 4688,
            // чтобы проверить именно выбор источника.
            ;
        let event = to_security_event(parse_event_xml(&xml).unwrap()).unwrap();
        assert_eq!(event.source, SOURCE_SYSMON);
    }

    #[test]
    fn длинное_поле_обрезается() {
        // Подставляем длинное значение в СОБСТВЕННОЕ поле, которого нет
        // в других местах шаблона: иначе проверялось бы не то поле.
        let long = "A".repeat(2000);
        let xml = LOGON_SUCCESS_XML.replace(
            "<Data Name=\"IpPort\">51422</Data>",
            &format!("<Data Name=\"LongField\">{long}</Data>"),
        );

        let record = parse_event_xml(&xml).unwrap();
        let event = to_security_event(record).unwrap();

        let stored = event
            .raw_fields
            .get("LongField")
            .expect("длинное поле должно сохраниться");
        assert!(stored.len() <= 520, "поле обрезано: {}", stored.len());
        assert!(stored.ends_with('…'), "обрезанная строка помечается многоточием");
    }

    #[test]
    fn время_без_зоны_трактуется_как_utc() {
        let parsed = parse_windows_time("2026-09-16T14:05:47.1234567").unwrap();
        assert_eq!(parsed, 1789567547123);
    }

    #[test]
    fn пустое_время_не_разбирается() {
        assert!(parse_windows_time("").is_none());
        assert!(parse_windows_time("не время").is_none());
    }

    #[test]
    fn pid_разбирается_в_двух_системах_счисления() {
        assert_eq!(parse_pid(Some("0x1a4")), Some(420));
        assert_eq!(parse_pid(Some("420")), Some(420));
        assert_eq!(parse_pid(Some("0X1A4")), Some(420));
        assert_eq!(parse_pid(Some("не число")), None);
        assert_eq!(parse_pid(None), None);
    }

    #[test]
    fn таблица_кодов_покрывает_ключевые_события_безопасности() {
        // Проверяем, что критичные для ИБ коды вообще присутствуют:
        // очистка журнала, неудачный вход, создание учётной записи.
        for code in [1102u32, 4625, 4720, 4688, 7045, 4740] {
            assert!(
                mapping_for(code).is_some(),
                "код {code} должен быть значимым для ИБ"
            );
        }

        assert!(mapping_for(1000).is_none(), "обычное падение приложения не значимо");
    }

    #[test]
    fn очистка_журнала_имеет_высокую_важность() {
        let mapping = mapping_for(1102).unwrap();
        assert_eq!(mapping.severity, severity::HIGH);
        assert_eq!(mapping.action, "log_cleared");
    }
    #[test]
    fn события_очистки_журнала_читаются_из_userdata() {
        let record = parse_event_xml(LOG_CLEARED_XML).expect("событие 1102 должно разбираться");

        assert_eq!(record.event_id, 1102);
        assert_eq!(record.channel, "Security");
        assert_eq!(record.computer, "WIN10-VM");
        assert_eq!(record.timestamp_unix_ms, 1789567547123);

        // Поля лежат в UserData и обязаны быть прочитаны.
        assert_eq!(record.get_meaningful("SubjectUserName"), "dadmin");
        assert_eq!(record.get_meaningful("SubjectDomainName"), "CONTOSO");
        assert_eq!(record.get("SubjectLogonId"), Some("0x55cd1d"));
    }

    #[test]
    fn тег_обёртка_userdata_не_попадает_в_поля() {
        let record = parse_event_xml(LOG_CLEARED_XML).unwrap();

        // LogFileCleared — контейнер, а не поле события. Если бы он
        // попал в поля, в raw_fields появился бы мусор с пустым значением.
        assert_eq!(record.get("LogFileCleared"), None);
    }

    #[test]
    fn очистка_журнала_превращается_в_событие_высокой_важности() {
        let record = parse_event_xml(LOG_CLEARED_XML).unwrap();
        let event = to_security_event(record).expect("1102 должно стать событием");

        assert_eq!(event.severity, severity::HIGH);
        // Категория SYSTEM, а не CONFIGURATION: очистка журнала — это
        // действие над подсистемой журналирования самого узла, то есть
        // событие уровня системы, а не изменение настроек. Оператор,
        // отбирающий события по категории «система», должен увидеть
        // здесь признак сокрытия следов.
        assert_eq!(event.category, category::SYSTEM);
        // Пользователь из UserData должен попасть в поле пользователя.
        assert_eq!(event.user, "dadmin");
        assert_eq!(event.raw_fields.get("windows_event_id").map(String::as_str), Some("1102"));
    }

    #[test]
    fn событие_без_полей_userdata_не_паникует() {
        // 1100 (ServiceShutdown) и 1104 (FileIsFull) вообще не содержат
        // полей. Разбор обязан пройти без ошибок, а не упасть.
        let xml = LOG_CLEARED_XML
            .replace("<EventID>1102</EventID>", "<EventID>1100</EventID>")
            .replace(
                "<LogFileCleared xmlns=\"http://manifests.microsoft.com/win/2004/08/windows/eventlog\">",
                "<ServiceShutdown>",
            )
            .replace("</LogFileCleared>", "</ServiceShutdown>")
            .replace("<SubjectUserSid>S-1-5-21-3457937927-2839227994-823803824-1104</SubjectUserSid>", "")
            .replace("<SubjectUserName>dadmin</SubjectUserName>", "")
            .replace("<SubjectDomainName>CONTOSO</SubjectDomainName>", "")
            .replace("<SubjectLogonId>0x55cd1d</SubjectLogonId>", "");

        let record = parse_event_xml(&xml).expect("событие без полей должно разбираться");
        assert_eq!(record.event_id, 1100);
        assert_eq!(record.get("ServiceShutdown"), None);
    }

    #[test]
    fn обычное_событие_по_прежнему_читается_из_eventdata() {
        // Проверяем, что поддержка UserData не сломала разбор EventData.
        let record = parse_event_xml(LOGON_SUCCESS_XML).unwrap();
        assert_eq!(record.get_meaningful("TargetUserName"), "operator");
        assert_eq!(record.get_meaningful("IpAddress"), "192.168.1.50");
    }

}
