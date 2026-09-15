//! Сбор телеметрии узла: ЦП, память, диски, сеть, процессы.
//!
//! Это «пульс» узла: консоль оператора показывает по этим данным
//! загрузку, расход памяти и список процессов. Снимок процессов
//! отправляется целиком — Core заменяет им предыдущий срез, поэтому
//! оператор всегда видит актуальную картину, а не накопленную историю.

use chrono::Utc;
use sysinfo::{Disks, Networks, Pid, ProcessesToUpdate, System, ThreadKind, Users};

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
            // Считаем только настоящие процессы: sysinfo включает в список
            // ещё и потоки (см. collect_processes), из-за чего число
            // процессов на узле было завышено в разы.
            process_count: self.process_count(),
            processes,
        }
    }

    /// Число настоящих процессов на узле, без потоков.
    fn process_count(&self) -> u32 {
        self.system
            .processes()
            .values()
            .filter(|p| !matches!(p.thread_kind(), Some(ThreadKind::Userland)))
            .count() as u32
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
            // Отбрасываем ПОТОКИ: sysinfo перечисляет не только процессы, но и
            // содержимое /proc/<PID>/task/*.
            //
            // Поток не является отдельным процессом — он делит адресное
            // пространство с родителем, поэтому и память, и командная строка
            // у него родительские. Без этой проверки снимок заполнялся
            // десятками записей вида «Compositor», «StyleThread#1»,
            // «WRRende~ckend#1» с памятью браузера, и настоящие процессы
            // (например, редактор) вытеснялись за предел ограничения.
            .filter(|(_, process)| !matches!(process.thread_kind(), Some(ThreadKind::Userland)))
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

    #[test]
    fn потоки_не_попадают_в_снимок_процессов() {
        // Создаём заведомые потоки, чтобы проверка не зависела от того,
        // есть ли они в системе в момент запуска теста. sysinfo перечисляет
        // содержимое /proc/<PID>/task/*, поэтому каждый такой поток
        // появляется в списке отдельной записью с памятью родителя.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let stop = stop.clone();
            handles.push(std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }));
        }

        let mut collector = TelemetryCollector::new(10_000);
        let report = collector.collect();

        let total = collector.system.processes().len();
        let threads = collector
            .system
            .processes()
            .values()
            .filter(|p| matches!(p.thread_kind(), Some(sysinfo::ThreadKind::Userland)))
            .count();

        assert!(
            threads > 0,
            "тест не создал ни одного потока — проверка ничего не проверяет"
        );

        // В снимке процессов потоков быть не должно.
        assert_eq!(
            report.processes.len() + threads,
            total,
            "в снимок попали потоки: всего {total}, потоков {threads}, в снимке {}",
            report.processes.len()
        );

        // Счётчик процессов тоже не должен учитывать потоки.
        assert_eq!(
            report.process_count as usize + threads,
            total,
            "счётчик процессов учитывает потоки"
        );

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in handles {
            h.join().ok();
        }
    }

    #[test]
    fn число_процессов_не_превышает_ограничение() {
        let mut collector = TelemetryCollector::new(50);
        let report = collector.collect();
        assert!(report.processes.len() <= 50);
    }

}
