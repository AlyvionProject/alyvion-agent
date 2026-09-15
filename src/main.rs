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

use std::time::Duration;

use anyhow::Context;
use tokio::sync::mpsc;
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
    // (ASP.NET Core) не отправляет их, пока не запишет первое сообщение —
    // то есть пока не получит AgentHello. Если ждать завершения вызова
    // перед отправкой регистрации, обе стороны будут ждать вечно.
    //
    // Send в канал лишь буферизует сообщение, поэтому вызов возвращается
    // сразу; ReceiverStream отдаст его, как только тело запроса начнёт
    // передаваться.
    send_hello(&out_tx, config).await?;

    let outbound = ReceiverStream::new(out_rx);
    let response = client.open_channel(Request::new(outbound)).await?;
    let mut inbound = response.into_inner();

    tracing::info!("двунаправленный поток открыт");

    // Периодические задачи агента. Каждая пишет в общий канал,
    // поэтому порядок сообщений в потоке сохраняется.
    let telemetry_task = tokio::spawn(telemetry_loop(config.clone(), out_tx.clone()));
    let heartbeat_task = tokio::spawn(heartbeat_loop(config.clone(), out_tx.clone()));

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
                if let Err(err) = handle_core_message(message, &out_tx, &executor).await {
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
async fn telemetry_loop(config: AgentConfig, tx: mpsc::Sender<AgentMessage>) {
    let mut collector = TelemetryCollector::new(config.max_processes);
    let mut ticker = tokio::time::interval(config.telemetry_interval());

    // Первый тик interval срабатывает сразу — для корректного расчёта
    // загрузки ЦП нужен интервал между замерами, поэтому пропускаем его.
    ticker.tick().await;

    loop {
        ticker.tick().await;

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
    }
}

/// Периодическая отправка heartbeat.
async fn heartbeat_loop(config: AgentConfig, tx: mpsc::Sender<AgentMessage>) {
    let mut ticker = tokio::time::interval(config.heartbeat_interval());
    ticker.tick().await;

    loop {
        ticker.tick().await;

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
) -> anyhow::Result<()> {
    match message.payload {
        Some(core_message::Payload::HelloAck(ack)) => {
            if ack.accepted {
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
fn os_version() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

/// Версия ядра.
fn kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
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
