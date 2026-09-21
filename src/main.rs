//! Агент Alyvion — сбор данных на защищаемом узле.
//!
//! Назначение: собирать телеметрию и события информационной безопасности,
//! передавать их в Core по защищённому каналу и исполнять разрешённые
//! команды реагирования.
//!
//! Модель взаимодействия — ОДИН двунаправленный gRPC-поток:
//!   * агент отправляет регистрацию, heartbeat, телеметрию, события
//!     и результаты реагирования;
//!   * Core присылает подтверждение регистрации и команды реагирования.
//!
//! Один поток выбран сознательно:
//!   * Core может доставить команду немедленно, а не ждать следующего
//!     опроса агентом — это критично для реагирования;
//!   * агент может находиться за NAT: соединение всегда исходящее;
//!   * открытый поток — это и есть точный признак «узел на связи»,
//!     не требующий отдельной проверки доступности.

mod config;
mod events;
mod response;
mod telemetry;
// Разбор журнала Windows. Не зависит от Windows: только преобразование
// XML в единую схему события, поэтому тестируется на любой платформе.
mod winevent;
// Чтение журнала Windows: под Windows использует Windows API,
// на прочих платформах — заглушка, возвращающая пустой список.
mod winlog;
// Декодирование вывода консольных программ Windows (CP866/CP1251):
// без него русский текст в отчётах реагирования превращался бы в мусор.
mod console;
// Выполнение команд Windows: подавление окна консоли и
// декодирование вывода в кодовой странице OEM.
mod sysops;
// Составление команд Windows (netsh, taskkill, net user) без
// зависимости от платформы — ради проверяемости тестами.
mod wincmd;

use std::time::Duration;

use anyhow::Context;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use config::AgentConfig;
use events::{EventCollector, category, severity};
use response::ResponseExecutor;
use telemetry::TelemetryCollector;

/// Сгенерированный из proto код контракта.
pub mod pb {
    tonic::include_proto!("alyvion");
}

use pb::alyvion_core_client::AlyvionCoreClient;
use pb::{
    AgentHello, AgentHeartbeat, AgentMessage, CoreMessage, SecurityEventBatch, agent_message,
    core_message,
};

/// Версия агента — уходит в Core и отображается в консоли.
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Интервалы работы, которые можно изменить на ходу.
///
/// ЗАЧЕМ ОТДЕЛЬНАЯ СТРУКТУРА. Раньше агент объявлял свои интервалы в
/// журнале при регистрации и на этом останавливался: значения из ответа
/// Core (`telemetry_interval_secs`, `heartbeat_interval_secs`) никуда
/// не применялись, а тикеры создавались ДО получения ответа — то есть
/// из локального конфигурационного файла. Оператор менял интервал
/// в Core и не видел никакого эффекта.
///
/// ПОЧЕМУ watch, А НЕ АТОМИКИ. Первая версия хранила значения в AtomicU64,
/// и цикл замечал смену только после очередного тика. Если локальный
/// интервал был большим (например, 99 секунд), первый тик ждал все 99
/// секунд, и присланное Core значение применялось лишь после этого —
/// то есть исправление не работало как раз в самом заметном случае.
/// watch-канал будит ожидающий цикл сразу, как только пришло новое
/// значение, поэтому смена интервала действует без задержки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Intervals {
    telemetry_secs: u64,
    heartbeat_secs: u64,
}

impl Intervals {
    fn new(telemetry_secs: u64, heartbeat_secs: u64) -> Self {
        Self {
            // Нижняя граница — не прихоть: при интервале 0 тикер срабатывает
            // непрерывно и загружает узел и канал связи вхолостую.
            telemetry_secs: telemetry_secs.max(1),
            heartbeat_secs: heartbeat_secs.max(1),
        }
    }

    fn telemetry(&self) -> Duration {
        Duration::from_secs(self.telemetry_secs)
    }

    fn heartbeat(&self) -> Duration {
        Duration::from_secs(self.heartbeat_secs)
    }

    /// Применяет интервалы, присланные Core при регистрации.
    ///
    /// Нулевые значения игнорируются: так агент переживает Core, который
    /// не заполнил поля, — вместо мгновенного цикла остаются прежние
    /// интервалы.
    fn apply(&self, telemetry_secs: u64, heartbeat_secs: u64) -> Self {
        Self {
            telemetry_secs: if telemetry_secs > 0 {
                telemetry_secs.max(1)
            } else {
                self.telemetry_secs
            },
            heartbeat_secs: if heartbeat_secs > 0 {
                heartbeat_secs.max(1)
            } else {
                self.heartbeat_secs
            },
        }
    }
}

/// Ждёт очередного срока, прерываясь при смене интервала.
///
/// Возвращает актуальный интервал. Ожидание прерывается, если пришло
/// новое значение, — поэтому смена настройки в Core применяется сразу,
/// а не после отработки прежнего, возможно очень длинного, интервала.
async fn wait_period(
    rx: &mut tokio::sync::watch::Receiver<Intervals>,
    current: Intervals,
    telemetry: bool,
) -> Intervals {
    let period = if telemetry {
        current.telemetry()
    } else {
        current.heartbeat()
    };

    tokio::select! {
        _ = tokio::time::sleep(period) => current,
        changed = rx.changed() => {
            // Ошибка означает, что отправитель закрыт — значит, агент
            // завершается. Возвращаем прежнее значение, цикл проверит
            // канал отправки и выйдет сам.
            match changed {
                Ok(()) => {
                    let updated = *rx.borrow_and_update();
                    tracing::info!(
                        telemetry_secs = updated.telemetry_secs,
                        heartbeat_secs = updated.heartbeat_secs,
                        "интервалы изменены Core"
                    );
                    updated
                }
                Err(_) => current,
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Разбор аргументов командной строки: --config <путь>, --help.
    let mut config_path = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config_path = Some(
                    args.next()
                        .context("после --config требуется путь к файлу")?
                        .into(),
                );
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-V" => {
                println!("alyvion-agent {AGENT_VERSION}");
                return Ok(());
            }
            other => anyhow::bail!("неизвестный параметр: {other} (см. --help)"),
        }
    }

    let config = AgentConfig::load(config_path)?;

    init_tracing();

    tracing::info!(
        agent_id = %config.agent_id,
        core_url = %config.core_url,
        version = AGENT_VERSION,
        реагирование = config.allow_response_actions,
        "агент Alyvion запускается"
    );

    // Внешний цикл переподключения: сеть и Core могут быть недоступны
    // в момент старта узла, поэтому агент обязан переживать это
    // и восстанавливать связь самостоятельно.
    let mut attempt: u32 = 0;

    loop {
        match run_session(&config).await {
            Ok(()) => {
                tracing::info!("сессия завершена штатно");
                attempt = 0;
            }
            Err(err) => {
                attempt = attempt.saturating_add(1);

                // Задержка растёт до 30 секунд, чтобы при недоступном Core
                // не забивать журнал и сеть бесконечными попытками.
                let delay = config
                    .reconnect_delay()
                    .saturating_mul(attempt.min(6))
                    .min(Duration::from_secs(30));

                tracing::warn!(
                    error = %err,
                    attempt,
                    delay_secs = delay.as_secs(),
                    "не удалось установить сеанс с Core, повтор через {delay:?}"
                );

                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Одна сессия связи с Core: от подключения до разрыва.
async fn run_session(config: &AgentConfig) -> anyhow::Result<()> {
    let endpoint = Endpoint::from_shared(config.core_url.clone())
        .context("некорректный адрес Core")?
        .connect_timeout(Duration::from_secs(10))
        // Долгий таймаут запроса: поток живёт постоянно, а не запрос-ответ.
        .timeout(Duration::from_secs(3600))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true);

    let channel: Channel = endpoint.connect().await.context("Core недоступен")?;
    let mut client = AlyvionCoreClient::new(channel);

    tracing::info!(core_url = %config.core_url, "соединение с Core установлено");

    // Канал исходящих сообщений. Ёмкость ограничена: если Core перестанет
    // успевать читать, агент не будет бесконечно копить данные в памяти.
    let (out_tx, out_rx) = mpsc::channel::<AgentMessage>(128);

    // ВАЖНО: регистрация ставится в очередь ДО открытия потока.
    //
    // Это не мелочь, а обход взаимной блокировки. Двунаправленный вызов
    // завершается только когда сервер отправит заголовки ответа, а сервер
    // не отправляет их, пока не запишет первое сообщение — то есть пока
    // не получит AgentHello. Если ждать завершения вызова перед отправкой
    // регистрации, обе стороны будут ждать вечно.
    //
    // Send в канал лишь буферизует сообщение, поэтому вызов возвращается
    // сразу; ReceiverStream отдаст его, как только тело запроса начнёт
    // передаваться.
    send_hello(&out_tx, config).await?;

    let outbound = ReceiverStream::new(out_rx);
    let response = client.open_channel(Request::new(outbound)).await?;
    let mut inbound = response.into_inner();

    tracing::info!("двунаправленный поток открыт");

    // Интервалы из локального файла — стартовые. Как только придёт ответ
    // Core, они будут заменены на присланные сервером: настройка задаётся
    // на стороне Core, а не на каждом узле отдельно.
    //
    // watch-канал, а не общая переменная: он не только хранит значение,
    // но и будит ожидающий цикл, поэтому новый интервал вступает в силу
    // немедленно, а не после отработки прежнего.
    let (intervals_tx, intervals_rx) = watch::channel(Intervals::new(
        config.telemetry_interval_secs,
        config.heartbeat_interval_secs,
    ));

    // Периодические задачи агента. Каждая пишет в общий канал,
    // поэтому порядок сообщений в потоке сохраняется.
    let telemetry_task = tokio::spawn(telemetry_loop(
        config.clone(),
        intervals_rx.clone(),
        out_tx.clone(),
    ));
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        intervals_rx.clone(),
        out_tx.clone(),
    ));

    // Сбор событий идёт в отдельной задаче с блокирующими вызовами
    // (чтение файлов, запуск journalctl), поэтому вынесен в spawn_blocking
    // внутри себя и не блокирует реактор Tokio.
    let events_task = tokio::spawn(events_loop(config.clone(), out_tx.clone()));

    let executor = std::sync::Arc::new(ResponseExecutor::new(config.allow_response_actions));

    // Читаем поток от Core до разрыва. Именно здесь приходят команды
    // реагирования, ради которых поток и сделан двунаправленным.
    let inbound_result = loop {
        match inbound.message().await {
            Ok(Some(message)) => {
                if let Err(err) =
                    handle_core_message(message, &out_tx, &executor, &intervals_tx).await
                {
                    tracing::warn!(error = %err, "ошибка обработки сообщения Core");
                }
            }
            Ok(None) => {
                tracing::info!("Core закрыл поток");
                break Ok(());
            }
            Err(status) => {
                tracing::warn!(code = ?status.code(), message = %status.message(), "поток прерван");
                break Err(anyhow::anyhow!("поток прерван: {}", status.message()));
            }
        }
    };

    telemetry_task.abort();
    heartbeat_task.abort();
    events_task.abort();

    drop(out_tx);

    inbound_result
}

/// Отправляет регистрационное сообщение.
async fn send_hello(tx: &mpsc::Sender<AgentMessage>, config: &AgentConfig) -> anyhow::Result<()> {
    let hello = AgentHello {
        agent_id: config.agent_id.clone(),
        hostname: config::hostname(),
        os_family: std::env::consts::OS.to_string(),
        os_version: os_version(),
        kernel_version: kernel_version(),
        architecture: std::env::consts::ARCH.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        ip_addresses: config::local_ip_addresses(),
        boot_time_unix_ms: (sysinfo::System::boot_time() as i64) * 1000,

        // Core ОБЯЗАН сверяться с этим списком и не присылать
        // неподдерживаемые команды.
        capabilities: config.declared_capabilities(),
        collectors: config.active_collectors(),
    };

    tracing::info!(
        capabilities = hello.capabilities.len(),
        collectors = ?hello.collectors,
        "регистрация узла отправлена"
    );

    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Hello(hello)),
    })
    .await
    .context("не удалось отправить регистрацию")?;

    Ok(())
}

/// Периодическая отправка телеметрии.
///
/// Интервал берётся из `Intervals` на каждой итерации, а не один раз при
/// создании тикера: Core может изменить его уже после подключения узла.
async fn telemetry_loop(
    config: AgentConfig,
    mut rx: tokio::sync::watch::Receiver<Intervals>,
    tx: mpsc::Sender<AgentMessage>,
) {
    let mut collector = TelemetryCollector::new(config.max_processes);
    let mut current = *rx.borrow_and_update();

    // Первое ожидание тоже прерываемое. Обычный sleep здесь был ошибкой:
    // он задерживал старт на локальный интервал (в проверке — 99 секунд),
    // поэтому присланное Core значение не применялось до его истечения.
    current = wait_period(&mut rx, current, true).await;

    loop {

        // Сбор телеметрии — синхронная работа с /proc: уводим её
        // с реактора, чтобы не задерживать обработку команд Core.
        let collector_ref = &mut collector;
        let report = tokio::task::block_in_place(|| collector_ref.collect());

        tracing::debug!(
            cpu = format!("{:.1}%", report.cpu_usage_percent),
            memory_used_kb = report.memory_used_kb,
            processes = report.processes.len(),
            "телеметрия собрана"
        );

        if tx
            .send(AgentMessage {
                payload: Some(agent_message::Payload::Telemetry(report)),
            })
            .await
            .is_err()
        {
            tracing::debug!("канал закрыт, отправка телеметрии остановлена");
            return;
        }

        // Ждём следующего срока; при смене интервала ожидание прерывается.
        current = wait_period(&mut rx, current, true).await;
    }
}

/// Периодическая отправка heartbeat.
async fn heartbeat_loop(
    mut rx: tokio::sync::watch::Receiver<Intervals>,
    tx: mpsc::Sender<AgentMessage>,
) {
    let mut current = *rx.borrow_and_update();
    // Первое ожидание прерываемое — по той же причине, что и у телеметрии.
    current = wait_period(&mut rx, current, false).await;

    loop {

        let heartbeat = AgentHeartbeat {
            timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
            uptime_secs: sysinfo::System::uptime() as i64,
            process_count: 0,
        };

        if tx
            .send(AgentMessage {
                payload: Some(agent_message::Payload::Heartbeat(heartbeat)),
            })
            .await
            .is_err()
        {
            return;
        }

        current = wait_period(&mut rx, current, false).await;
    }
}

/// Периодический сбор событий безопасности.
async fn events_loop(config: AgentConfig, tx: mpsc::Sender<AgentMessage>) {
    let mut collector = EventCollector::new(config.state_dir.clone(), config.log_tail_lines);
    let toggles = config.collectors.clone();
    let extra_paths = config.extra_log_paths.clone();
    let interval = config.events_interval();

    loop {
        tokio::time::sleep(interval).await;

        // Сбор событий блокирующий (файлы, запуск journalctl), поэтому
        // выполняется в отдельном потоке пула. Сборщик передаётся по
        // значению и возвращается обратно: так задача не удерживает
        // заимствование между вызовами и сохраняет позиции чтения.
        let toggles = toggles.clone();
        let mut moved = std::mem::replace(
            &mut collector,
            EventCollector::new(config.state_dir.clone(), config.log_tail_lines),
        );

        let extra_paths = extra_paths.clone();
        let collected = tokio::task::spawn_blocking(move || {
            let events = moved.collect(&toggles, &extra_paths);
            (moved, events)
        })
        .await;

        let events = match collected {
            Ok((returned, events)) => {
                collector = returned;
                events
            }
            Err(err) => {
                tracing::error!(error = %err, "задача сбора событий завершилась ошибкой");
                return;
            }
        };

        if events.is_empty() {
            continue;
        }

        // Ограничиваем размер пакета: контракт и Core рассчитаны
        // на разумный объём за один обмен.
        let batch: Vec<_> = events.into_iter().take(config.log_tail_lines).collect();
        let count = batch.len();

        tracing::debug!(events = count, "собраны события безопасности");

        if tx
            .send(AgentMessage {
                payload: Some(agent_message::Payload::Events(SecurityEventBatch {
                    events: batch,
                })),
            })
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Обрабатывает сообщение, пришедшее от Core.
async fn handle_core_message(
    message: CoreMessage,
    tx: &mpsc::Sender<AgentMessage>,
    executor: &std::sync::Arc<ResponseExecutor>,
    intervals: &watch::Sender<Intervals>,
) -> anyhow::Result<()> {
    match message.payload {
        Some(core_message::Payload::HelloAck(ack)) => {
            if ack.accepted {
                // Интервалы, присланные Core, применяются к уже работающим
                // циклам. Раньше они только попадали в журнал, и настройка
                // Core ни на что не влияла.
                //
                // Приведение через max(0): в proto поле объявлено uint32,
                // но Rust-стаб отдаёт i32, поэтому отрицательное значение
                // теоретически возможно — его нужно отсечь, а не паниковать.
                // send_replace, а не send: он не падает, если приёмников
                // ещё нет, и всегда записывает новое значение.
                let updated = intervals.borrow().apply(
                    ack.telemetry_interval_secs.max(0) as u64,
                    ack.heartbeat_interval_secs.max(0) as u64,
                );
                intervals.send_replace(updated);

                tracing::info!(
                    server_version = %ack.server_version,
                    telemetry_interval = ack.telemetry_interval_secs,
                    heartbeat_interval = ack.heartbeat_interval_secs,
                    реагирование = ack.allow_response_actions,
                    "узел зарегистрирован в Core: {}",
                    ack.message
                );
            } else {
                tracing::error!("Core отклонил регистрацию узла: {}", ack.message);
                anyhow::bail!("регистрация отклонена: {}", ack.message);
            }
        }

        Some(core_message::Payload::Command(command)) => {
            // Выполнение может занимать время (запуск утилит), поэтому
            // уводим его с реактора, чтобы не блокировать приём
            // следующих сообщений Core.
            let executor = executor.clone();
            let result = tokio::task::spawn_blocking(move || executor.execute(&command))
                .await
                .context("задача выполнения команды прервана")?;

            tracing::info!(
                command_id = %result.command_id,
                success = result.success,
                "результат реагирования отправляется в Core"
            );

            tx.send(AgentMessage {
                payload: Some(agent_message::Payload::CommandResult(result)),
            })
            .await
            .context("не удалось отправить результат реагирования")?;
        }

        Some(core_message::Payload::Ack(ack)) => {
            tracing::debug!(
                success = ack.success,
                accepted = ack.accepted_count,
                "подтверждение Core"
            );
        }

        Some(core_message::Payload::Ping(ping)) => {
            tracing::trace!(timestamp = ping.timestamp_unix_ms, "ping от Core");
        }

        None => tracing::warn!("получено сообщение Core без полезной нагрузки"),
    }

    Ok(())
}

/// Настраивает журналирование.
fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("alyvion_agent=info,warn"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();
}

/// Описание операционной системы из `/etc/os-release`.
/// Определяет название операционной системы.
///
/// ПОЧЕМУ ЧЕРЕЗ `sysinfo`, А НЕ ЧЕРЕЗ `/etc/os-release`. Прежняя версия
/// читала файл `/etc/os-release`, которого в Windows НЕТ. На Windows она
/// всегда возвращала безликое «windows» вместо, например, «Windows 10 Pro»,
/// и оператор не мог отличить редакцию. `sysinfo` умеет определять
/// название на всех поддерживаемых платформах.
///
/// Чтение `/etc/os-release` сохранено как уточнение для Linux: там оно
/// даёт более точное описание (например, «Fedora Linux 42»), чем
/// обобщённое имя от `sysinfo`.
fn os_version() -> String {
    // На Linux предпочитаем точное название из файла выпуска.
    #[cfg(not(windows))]
    if let Some(pretty) = read_linux_pretty_name() {
        return pretty;
    }

    sysinfo::System::long_os_version()
        .or_else(|| sysinfo::System::name())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

/// Читает поле `PRETTY_NAME` из `/etc/os-release`.
///
/// Возвращает `None`, если файла нет или поле отсутствует.
#[cfg(not(windows))]
fn read_linux_pretty_name() -> Option<String> {
    parse_pretty_name(&std::fs::read_to_string("/etc/os-release").ok()?)
}

/// Разбирает `PRETTY_NAME` из содержимого файла выпуска.
///
/// Вынесено отдельно от чтения файла, чтобы разбор можно было проверить
/// тестами: сама логика (кавычки, пробелы, отсутствие поля) — источник
/// ошибок, а не обращение к файловой системе.
#[cfg(not(windows))]
fn parse_pretty_name(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=")
            .map(|value| value.trim().trim_matches('"').trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

/// Версия ядра операционной системы.
///
/// Прежняя версия читала `/proc/sys/kernel/osrelease` — файла с таким
/// путём в Windows не существует, поэтому на Windows версия ядра всегда
/// была пустой. `sysinfo` возвращает её на всех платформах: на Windows
/// это версия ядра NT, что и требуется для инвентаризации.
fn kernel_version() -> String {
    sysinfo::System::kernel_version()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_default()
}

fn print_help() {
    println!(
        r#"Агент Alyvion {AGENT_VERSION}

Использование:
    alyvion-agent [--config <файл>]

Параметры:
    -c, --config <файл>   путь к файлу конфигурации TOML
    -h, --help            показать эту справку
    -V, --version         показать версию

Переменные окружения (переопределяют файл конфигурации):
    ALYVION_CORE_URL          адрес gRPC-сервера Core
    ALYVION_AGENT_ID          идентификатор узла
    ALYVION_TELEMETRY_INTERVAL интервал телеметрии, секунды
    ALYVION_HEARTBEAT_INTERVAL интервал heartbeat, секунды
    ALYVION_EVENTS_INTERVAL    интервал сбора событий, секунды
    ALYVION_MAX_PROCESSES      ограничение процессов в снимке
    ALYVION_ALLOW_RESPONSE     разрешить реагирование (true/false)
    ALYVION_STATE_DIR          каталог состояния агента
    RUST_LOG                   уровень журналирования
"#
    );
}

/// События самого агента: используются для регистрации значимых
/// действий (запуск, выполнение реагирования) в общем потоке.
#[allow(dead_code)]
pub fn agent_event(action: &str, message: String) -> pb::SecurityEvent {
    pb::SecurityEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
        source: "agent".to_string(),
        category: category::SYSTEM.to_string(),
        action: action.to_string(),
        severity: severity::INFO.to_string(),
        outcome: "success".to_string(),
        message,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    /// Проверяет разбор файла выпуска Linux. Разбор вынесен в отдельную
    /// функцию именно ради этой проверки: ошибки в кавычках и пробелах
    /// заметны только на конкретных примерах.
    #[cfg(not(windows))]
    #[test]
    fn название_системы_извлекается_из_os_release() {
        let content = "NAME=Fedora\nPRETTY_NAME=\"Fedora Linux 42 (Workstation)\"\nID=fedora\n";
        assert_eq!(
            super::parse_pretty_name(content).as_deref(),
            Some("Fedora Linux 42 (Workstation)")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn название_системы_без_кавычек_тоже_читается() {
        let content = "PRETTY_NAME=Debian GNU/Linux 12\n";
        assert_eq!(
            super::parse_pretty_name(content).as_deref(),
            Some("Debian GNU/Linux 12")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn отсутствие_поля_не_паникует() {
        // Файл без PRETTY_NAME — не ошибка: вызывающий код перейдёт
        // к определению через sysinfo.
        assert_eq!(super::parse_pretty_name("NAME=Fedora\nID=fedora\n"), None);
        assert_eq!(super::parse_pretty_name(""), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn пустое_значение_считается_отсутствующим() {
        // Пустое PRETTY_NAME не должно подменять настоящее название
        // системы пустой строкой в карточке узла.
        assert_eq!(super::parse_pretty_name("PRETTY_NAME=\"\"\n"), None);
        assert_eq!(super::parse_pretty_name("PRETTY_NAME=\n"), None);
    }

    /// Определение системы работает на этой платформе и не возвращает
    /// пустую строку: иначе в карточке узла был бы прочерк.
    #[test]
    fn определение_системы_даёт_непустой_результат() {
        let name = super::os_version();
        assert!(!name.trim().is_empty(), "название системы не должно быть пустым");
    }

    /// Версия ядра определяется на обеих платформах. Именно эта функция
    /// раньше читала /proc, которого нет в Windows.
    #[test]
    fn версия_ядра_определяется() {
        let version = super::kernel_version();
        assert!(
            !version.trim().is_empty(),
            "версия ядра не должна быть пустой"
        );
    }
}
