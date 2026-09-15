//! Сбор телеметрии узла: ЦП, память, диски, сеть, процессы.
//!
//! Это «пульс» узла: консоль оператора показывает по этим данным
//! загрузку, расход памяти и список процессов. Снимок процессов
//! отправляется целиком — Core заменяет им предыдущий срез, поэтому
//! оператор всегда видит актуальную картину, а не накопленную историю.

use chrono::Utc;
use sysinfo::{Disks, Networks, Pid, ProcessesToUpdate, System, Users};

use crate::pb::{ProcessInfo, TelemetryReport};

/// Состояние сборщика между опросами.
///
/// Важно хранить `System` между вызовами: sysinfo считает загрузку ЦП
/// как разницу между двумя замерами, поэтому одноразовый `new_all()`
/// всегда даёт нулевые значения.
pub struct TelemetryCollector {
    system: System,
    disks: Disks,
    networks: Networks,
    users: Users,
    max_processes: usize,
}

impl TelemetryCollector {
    pub fn new(max_processes: usize) -> Self {
        Self {
            system: System::new_all(),
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            users: Users::new_with_refreshed_list(),
            max_processes,
        }
    }

    /// Делает очередной замер и формирует отчёт для Core.
    pub fn collect(&mut self) -> TelemetryReport {
        // Порядок важен: сначала обновляем счётчики, потом читаем.
        self.system
            .refresh_processes(ProcessesToUpdate::All, true);
        self.system.refresh_cpu_all();
        self.system.refresh_memory();
        self.disks.refresh();
        self.networks.refresh();

        let now_ms = Utc::now().timestamp_millis();

        let load = System::load_average();

        // Диски суммируем по всем смонтированным файловым системам.
        let (disk_total, disk_free) = self
            .disks
            .list()
            .iter()
            .fold((0u64, 0u64), |(total, free), disk| {
                (
                    total + disk.total_space(),
                    free + disk.available_space(),
                )
            });

        // Сетевые счётчики — суммарно с момента загрузки узла.
        let (net_rx, net_tx) = self
            .networks
            .list()
            .values()
            .fold((0u64, 0u64), |(rx, tx), data| {
                (rx + data.total_received(), tx + data.total_transmitted())
            });

        let processes = self.collect_processes();

        TelemetryReport {
            timestamp_unix_ms: now_ms,
            cpu_usage_percent: self.system.global_cpu_usage() as f64,
            cpu_cores: self.system.cpus().len() as u32,
            load_avg_1: load.one,
            load_avg_5: load.five,
            load_avg_15: load.fifteen,

            // sysinfo отдаёт байты — переводим в килобайты, как в контракте.
            memory_total_kb: self.system.total_memory() / 1024,
            memory_used_kb: self.system.used_memory() / 1024,
            swap_total_kb: self.system.total_swap() / 1024,
            swap_used_kb: self.system.used_swap() / 1024,

            disk_total_kb: disk_total / 1024,
            disk_used_kb: disk_total.saturating_sub(disk_free) / 1024,

            net_rx_kb: net_rx / 1024,
            net_tx_kb: net_tx / 1024,

            uptime_secs: System::uptime() as i64,
            process_count: self.system.processes().len() as u32,
            processes,
        }
    }

    /// Снимок процессов, отсортированный по нагрузке.
    ///
    /// Ограничение нужно, чтобы пакет не разрастался: на реальном узле
    /// процессов могут быть тысячи, а оператору интересны самые
    /// нагруженные. Ограничение задаётся в конфигурации.
    fn collect_processes(&self) -> Vec<ProcessInfo> {
        let mut processes: Vec<ProcessInfo> = self
            .system
            .processes()
            .iter()
            .map(|(pid, process)| {
                let user = process
                    .user_id()
                    .and_then(|uid| self.users.get_user_by_id(uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_default();

                ProcessInfo {
                    pid: pid.as_u32(),
                    ppid: process.parent().map(Pid::as_u32).unwrap_or(0),
                    name: process.name().to_string_lossy().to_string(),
                    exe_path: process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    command_line: process
                        .cmd()
                        .iter()
                        .map(|a| a.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(" "),
                    user,
                    cpu_usage: process.cpu_usage() as f64,
                    memory_kb: process.memory() / 1024,
                    status: process.status().to_string(),
                    start_time_unix_ms: (process.start_time() as i64) * 1000,
                }
            })
            .collect();

        // Сортируем по потреблению памяти: оно стабильнее мгновенного ЦП
        // и лучше отражает значимость процесса для узла.
        processes.sort_by(|a, b| b.memory_kb.cmp(&a.memory_kb));
        processes.truncate(self.max_processes);

        processes
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn телеметрия_содержит_осмысленные_значения() {
        let mut collector = TelemetryCollector::new(50);
        // Первый замер инициализирует счётчики, второй даёт реальную загрузку.
        let _ = collector.collect();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let report = collector.collect();

        assert!(report.cpu_cores >= 1, "должно быть хотя бы одно ядро");
        assert!(report.memory_total_kb > 0, "объём памяти должен быть известен");
        assert!(report.memory_used_kb <= report.memory_total_kb);
        assert!(report.process_count >= 1, "на узле есть хотя бы один процесс");
        assert!(report.uptime_secs > 0, "узел работает не первую секунду");
        assert!(
            report.disk_total_kb >= report.disk_used_kb,
            "занятое место не может превышать общий объём"
        );
    }

    #[test]
    fn ограничение_числа_процессов_соблюдается() {
        let mut collector = TelemetryCollector::new(5);
        let report = collector.collect();
        assert!(report.processes.len() <= 5);
    }

    #[test]
    fn процессы_отсортированы_по_памяти_по_убыванию() {
        let mut collector = TelemetryCollector::new(100);
        let report = collector.collect();
        let memory: Vec<u64> = report.processes.iter().map(|p| p.memory_kb).collect();
        let mut sorted = memory.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(memory, sorted);
    }
}
