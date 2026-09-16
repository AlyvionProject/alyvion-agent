//! Выполнение команд Windows.
//!
//! ЗАЧЕМ ОТДЕЛЬНЫЙ МОДУЛЬ. Составление команд живёт в `wincmd.rs` и не
//! зависит от платформы, поэтому проверяется тестами на сборочной машине.
//! Здесь — только ЗАПУСК: он требует Windows API и потому компилируется
//! исключительно под Windows.
//!
//! ДВА СВОЙСТВА, КОТОРЫЕ ЗДЕСЬ ОБЕСПЕЧИВАЮТСЯ.
//!
//! 1. Окно консоли не появляется. Агент работает как служба, но если
//!    запустить его из сеанса пользователя, каждый вызов `taskkill` или
//!    `netsh` открывал бы чёрное окно на экране. Флаг `CREATE_NO_WINDOW`
//!    это подавляет.
//!
//! 2. Русский текст читается правильно. Утилиты Windows пишут в кодовой
//!    странице консоли (CP866), а не в UTF-8. Кодировка определяется
//!    через `GetOEMCP` и применяется при разборе вывода — иначе причина
//!    отказа выглядела бы как «╬°шсЄр».

// Импорт нужен только ветке Windows: на других платформах запуск
// не выполняется, и подключение было бы неиспользуемым.
#[cfg(windows)]
use crate::console::decode_console_output;
use crate::wincmd::CommandSpec;

/// Итог запуска программы Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Программа завершилась успешно (код возврата 0).
    pub success: bool,
    /// Вывод программы, приведённый к читаемому виду.
    pub output: String,
}

impl ExecutionResult {
    /// Сообщение об отказе, пригодное для показа оператору.
    ///
    /// ПОЧЕМУ НЕ ПО КОДУ ВОЗВРАТА. Коды возврата утилит Windows
    /// не документированы как контракт (например, для `taskkill` код
    /// «процесс не найден» официально не зафиксирован), поэтому
    /// полагаться на конкретные числа нельзя. Показывается тот текст,
    /// который выдала сама утилита: он и есть источник истины.
    pub fn failure_message(&self, spec: &CommandSpec) -> String {
        if self.output.is_empty() {
            format!("{}: команда завершилась с ошибкой (вывод пуст)", spec.program)
        } else {
            self.output.clone()
        }
    }
}

/// Определяет кодовую страницу консоли на этой машине.
///
/// Вызывается один раз при старте и переиспользуется: значение в рамках
/// сеанса не меняется, а системный вызов на каждую команду был бы лишним.
#[cfg(windows)]
pub fn console_code_page() -> u32 {
    // GetOEMCP возвращает кодовую страницу OEM (для русской Windows — 866).
    // Возвращаемое значение всегда ненулевое, поэтому проверка не нужна.
    unsafe { windows::Win32::Globalization::GetOEMCP() }
}

/// Заглушка для не-Windows: кодовая страница не определена.
///
/// Возвращается значение по умолчанию, чтобы код, вызывающий эту функцию,
/// оставался платформенно-независимым.
#[cfg(not(windows))]
pub fn console_code_page() -> u32 {
    crate::console::FALLBACK_CODE_PAGE
}

/// Запускает программу и возвращает её вывод.
///
/// ПОЧЕМУ ЗАПУСК БЕЗ ОБОЛОЧКИ. Программа вызывается напрямую, со списком
/// аргументов. Оболочка (`cmd /c`) не используется: она интерпретировала
/// бы спецсимволы, и значение, пришедшее от Core, могло бы выполнить
/// произвольную команду. Прямой запуск исключает такую подстановку.
#[cfg(windows)]
pub fn execute(spec: &CommandSpec, code_page: u32) -> ExecutionResult {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    // CREATE_NO_WINDOW подавляет появление окна консоли.
    // Значение 0x08000000 (134217728) — из заголовков Windows.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let output = Command::new(&spec.program)
        .args(&spec.args)
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match output {
        Ok(output) => {
            // Успех определяется кодом возврата: он не зависит от языка
            // системы, в отличие от текста вывода.
            let success = output.status.success();

            // Диагностика важнее обычного вывода: именно в stderr
            // утилиты Windows пишут причину отказа.
            let bytes = if output.stdout.is_empty() {
                output.stderr.clone()
            } else if output.stderr.is_empty() {
                output.stdout.clone()
            } else {
                // Есть и то и другое: показываем обе части, потому что
                // причина отказа бывает в любой из них.
                let mut combined = output.stdout.clone();
                combined.push(b'\n');
                combined.extend_from_slice(&output.stderr);
                combined
            };

            ExecutionResult {
                success,
                output: decode_console_output(&bytes, code_page),
            }
        }
        Err(err) => ExecutionResult {
            success: false,
            output: format!("не удалось запустить {}: {err}", spec.program),
        },
    }
}

/// Заглушка для не-Windows.
///
/// Возвращает неуспех с понятным текстом. Это защита от молчаливого
/// бездействия: если такой вызов когда-нибудь произойдёт на Linux,
/// оператор увидит причину, а не «команда выполнена» без результата.
#[cfg(not(windows))]
pub fn execute(spec: &CommandSpec, code_page: u32) -> ExecutionResult {
    let _ = code_page;
    ExecutionResult {
        success: false,
        output: format!(
            "{}: действие реагирования Windows недоступно на этой платформе",
            spec.program
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn пустой_вывод_даёт_понятное_сообщение_об_отказе() {
        let result = ExecutionResult {
            success: false,
            output: String::new(),
        };

        let spec = CommandSpec {
            program: "taskkill".to_string(),
            args: vec![],
        };

        let message = result.failure_message(&spec);
        assert!(message.contains("taskkill"));
        assert!(message.contains("вывод пуст"));
    }

    #[test]
    fn текст_утилиты_используется_как_сообщение_об_отказе() {
        // Коды возврата утилит Windows не документированы, поэтому
        // источник истины — текст, который вернула сама утилита.
        let result = ExecutionResult {
            success: false,
            output: "ERROR: The process \"9999\" not found.".to_string(),
        };

        let spec = CommandSpec {
            program: "taskkill".to_string(),
            args: vec![],
        };

        assert_eq!(
            result.failure_message(&spec),
            "ERROR: The process \"9999\" not found."
        );
    }

    #[test]
    fn на_не_windows_действие_явно_сообщает_о_недоступности() {
        // Защита от молчаливого бездействия: вызов Windows-действия
        // на Linux обязан вернуть неуспех с объяснением, а не «выполнено».
        if cfg!(not(windows)) {
            let spec = CommandSpec {
                program: "netsh".to_string(),
                args: vec!["advfirewall".to_string()],
            };

            let result = execute(&spec, 866);
            assert!(!result.success);
            assert!(result.output.contains("недоступно"));
        }
    }

    #[test]
    fn кодовая_страница_по_умолчанию_на_не_windows_известна() {
        if cfg!(not(windows)) {
            assert_eq!(console_code_page(), crate::console::FALLBACK_CODE_PAGE);
        }
    }
}
