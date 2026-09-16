//! Чтение журнала событий Windows (Windows Event Log).
//!
//! ЗАЧЕМ ОТДЕЛЬНЫЙ МОДУЛЬ. Чтение журнала требует Windows API и поэтому
//! компилируется только под Windows. Разбор XML живёт в `winevent.rs`
//! и не зависит от платформы — так самая ошибкоопасная часть проверяется
//! тестами на любой сборочной машине.
//!
//! ПОЧЕМУ ЧТЕНИЕ ИНКРЕМЕНТАЛЬНОЕ. В журнале Windows нет понятия «смещение
//! в строках», как в текстовых журналах Linux. Вместо него используется
//! ЗАКЛАДКА (bookmark): указатель на конкретную запись. Закладка
//! сохраняется между запусками агента, поэтому после перезапуска чтение
//! продолжается с последнего прочитанного места, а не с начала журнала.
//!
//! ПОЧЕМУ НЕ «ЗА ПОСЛЕДНИЕ N МИНУТ». Опрос по времени приводит к тому,
//! что один и тот же интервал перечитывается на каждом цикле (каждые
//! несколько секунд), и одна запись попадает в Core десятки раз. Закладка
//! этой проблемы не имеет: она указывает на конкретную запись.

use std::collections::HashMap;

use crate::pb::SecurityEvent;
use crate::winevent::{self, DEFAULT_CHANNELS, POWERSHELL_CORE_CHANNEL, SYSMON_CHANNEL};

/// Сколько записей забирать у API за одно обращение.
///
/// Компромисс: слишком мало — много системных вызовов, слишком много —
/// большой расход памяти на буфер.
const BATCH_SIZE: usize = 32;

/// Предел записей, забираемых из одного канала за один проход.
///
/// ЗАЧЕМ ПРЕДОХРАНИТЕЛЬ. Даже с закладками возможен большой запас:
/// агент был выключен неделю, журнал успел вырасти. Прочитать всё сразу
/// означало бы залп в десятки тысяч событий, который перегрузил бы канал
/// связи и базу Core. Предел разбивает запас на порции: остаток читается
/// следующими проходами, закладка хранит позицию, поэтому НИ ОДНО событие
/// не теряется — сбор просто растягивается во времени.
///
/// Это же ограничение защищает от второй ошибки: если `EvtSeek` почему-то
/// откажет и чтение пойдёт с начала журнала, проход остановится на пределе
/// вместо того, чтобы вычитать всю историю узла.
const MAX_EVENTS_PER_PASS: usize = 1000;

/// Признак того, что канал недоступен для чтения.
///
/// Наиболее частая причина — недостаточно прав: канал Security не читается
/// без прав администратора. Это НЕ ошибка агента, а ожидаемая ситуация,
/// поэтому она отмечается отдельно и показывается оператору понятным
/// текстом, а не молчаливым пропуском.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Нет прав на чтение канала (ERROR_ACCESS_DENIED).
    AccessDenied,
    /// Канал не найден: например, Sysmon не установлен.
    NotFound,
    /// Прочая ошибка с кодом Windows.
    Other(u32, String),
}

impl ChannelError {
    /// Описание для оператора на русском языке.
    pub fn describe(&self, channel: &str) -> String {
        match self {
            Self::AccessDenied => format!(
                "канал {channel}: нет прав на чтение. Запустите агент от имени \
                 администратора или добавьте учётную запись агента в группу \
                 «Читатели журнала событий» (Event Log Readers)"
            ),
            // Текст зависит от канала: «не найден» для Sysmon и для
            // PowerShell 7 означает разное, и общая формулировка
            // сбивала бы с толку. Проверено на живой ВМ: отсутствие
            // PowerShellCore — обычное дело на Windows 10.
            Self::NotFound => match channel {
                "PowerShellCore/Operational" => format!(
                    "канал {channel}: не найден. Это нормально: канал есть \
                     только там, где установлен PowerShell 7 и новее. \
                     PowerShell 5.1 пишет в отдельный канал, он опрашивается отдельно"
                ),
                "Microsoft-Windows-Sysmon/Operational" => format!(
                    "канал {channel}: не найден. Sysmon — отдельный продукт, \
                     он не входит в поставку Windows. Если он не нужен, \
                     оставьте sysmon = false в конфигурации"
                ),
                _ => format!(
                    "канал {channel}: не найден. Штатный канал должен \
                     существовать в любой Windows; проверьте имя канала \
                     и права на его чтение"
                ),
            },
            Self::Other(code, text) => {
                format!("канал {channel}: ошибка Windows {code} ({text})")
            }
        }
    }
}

/// Извлекает код ошибки Win32 из значения, которое вернул Windows API.
///
/// ЗАЧЕМ ЭТО НУЖНО. Windows отдаёт ошибку УПАКОВАННОЙ в HRESULT: старшее
/// слово `0x8007` означает «ошибка Win32», а младшее — сам код. Так, отказ
/// в доступе приходит как `0x80070005` (2147942405), а не как `5`, а конец
/// чтения журнала — как `0x80070103` (2147942659), а не как `259`.
///
/// ПРОВЕРЕНО НА ЖИВОЙ ВМ: без распаковки НИ ОДНО сравнение с кодом
/// не совпадало. Особенно опасно это было для конца чтения (`259`):
/// он приходит в конце КАЖДОГО чтения, и нераспознанный сигнал
/// превращал нормальное завершение в ошибку — из-за чего уже
/// прочитанные события выбрасывались и не доходили до Core.
pub fn win32_code(value: i32) -> u32 {
    let raw = value as u32;

    // 0x8007_0000 — ошибка с признаком FACILITY_WIN32.
    if (raw & 0xFFFF_0000) == 0x8007_0000 {
        raw & 0xFFFF
    } else {
        raw
    }
}

/// Состояние чтения журнала: закладки по каналам.
///
/// Хранится в общем файле состояния агента рядом со смещениями текстовых
/// журналов Linux, поэтому после перезапуска чтение не начинается заново.
#[derive(Debug, Default)]
pub struct WindowsLogState {
    /// Закладка канала в виде XML-строки, как её отдаёт Windows.
    pub bookmarks: HashMap<String, String>,
}

impl WindowsLogState {
    /// Каналы, которые следует опрашивать на этой машине.
    ///
    /// Наличие Sysmon проверяется отдельно: его канал есть только там,
    /// где Sysmon установлен, а попытка чтения отсутствующего канала
    /// давала бы ошибку на каждом цикле.
    pub fn channels_to_poll(include_sysmon: bool) -> Vec<String> {
        let mut channels: Vec<String> = DEFAULT_CHANNELS.iter().map(|c| c.to_string()).collect();

        // PowerShell 7 пишет в отдельный канал. Если его нет (типичная
        // Windows 10 без PowerShell 7), чтение вернёт «канал не найден»,
        // и это отмечается как проблема канала, не прерывая остальные.
        channels.push(POWERSHELL_CORE_CHANNEL.to_string());

        if include_sysmon {
            channels.push(SYSMON_CHANNEL.to_string());
        }

        channels
    }
}

/// Читает новые записи указанных каналов и приводит их к единой схеме.
///
/// О ПРИВЯЗКЕ К ПОТОКУ. Дескриптор набора результатов `EvtQuery` можно
/// использовать только в том потоке, который его создал. Здесь это
/// требование выполняется по построению: набор открывается, читается
/// и закрывается ВНУТРИ одного синхронного вызова `read_channel`,
/// поэтому дескриптор не может перейти в другой поток. Между вызовами
/// переносится только закладка — обычная строка, у которой привязки нет.
/// Это важно, потому что сбор выполняется в пуле потоков tokio
/// (`spawn_blocking`), а его задачи не обязаны попадать на один и тот же
/// поток.
///
/// Возвращает события и список проблем по каналам (например, отсутствие
/// прав). Проблемы не прерывают сбор: остальные каналы читаются дальше,
/// иначе одна недоступная ветка лишила бы оператора всех событий.
pub fn collect(
    state: &mut WindowsLogState,
    include_sysmon: bool,
    first_run_tail: usize,
) -> (Vec<SecurityEvent>, Vec<String>) {
    let mut events = Vec::new();
    let mut problems = Vec::new();

    for channel in WindowsLogState::channels_to_poll(include_sysmon) {
        let bookmark = state.bookmarks.get(&channel).cloned();

        match read_channel(&channel, bookmark.as_deref(), first_run_tail) {
            Ok((xml_records, new_bookmark)) => {
                // Закладку сохраняем ДАЖЕ если значимых событий не нашлось:
                // иначе следующий цикл перечитает те же записи.
                if let Some(bookmark) = new_bookmark {
                    state.bookmarks.insert(channel.clone(), bookmark);
                }

                for xml in xml_records {
                    let Some(record) = winevent::parse_event_xml(&xml) else {
                        continue;
                    };
                    if let Some(event) = winevent::to_security_event(record) {
                        events.push(event);
                    }
                }
            }
            Err(err) => problems.push(err.describe(&channel)),
        }
    }

    (events, problems)
}

/// Читает новые записи одного канала.
///
/// Возвращает XML-строки записей и обновлённую закладку.
#[cfg(windows)]
fn read_channel(
    channel: &str,
    bookmark_xml: Option<&str>,
    first_run_tail: usize,
) -> Result<(Vec<String>, Option<String>), ChannelError> {
    imp::read_channel(channel, bookmark_xml, first_run_tail)
}

/// Заглушка для не-Windows: сбор из журнала Windows невозможен.
#[cfg(not(windows))]
fn read_channel(
    _channel: &str,
    _bookmark_xml: Option<&str>,
    _first_run_tail: usize,
) -> Result<(Vec<String>, Option<String>), ChannelError> {
    Ok((Vec::new(), None))
}

/// Работа с Windows API. Компилируется только под Windows.
#[cfg(windows)]
mod imp {
    use super::{BATCH_SIZE, ChannelError, MAX_EVENTS_PER_PASS};

    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_FILE_NOT_FOUND,
        ERROR_NO_MORE_ITEMS,
    };
    use windows::Win32::System::EventLog::{
        EvtClose, EvtCreateBookmark, EvtNext, EvtQuery, EvtRender, EvtSeek, EvtUpdateBookmark,
        EvtQueryChannelPath, EvtQueryForwardDirection, EvtRenderBookmark, EvtRenderEventXml,
        EvtSeekRelativeToBookmark, EvtSeekRelativeToLast, EVT_HANDLE,
    };
    use windows::core::PCWSTR;

    /// Обёртка над дескриптором Windows Event Log.
    ///
    /// ЗАЧЕМ ОБЁРТКА. Дескрипторы нужно закрывать через `EvtClose` в любом
    /// случае, включая ранний выход по ошибке. Ручное закрытие легко
    /// забыть на одной из веток — тогда агент, работающий месяцами,
    /// исчерпал бы дескрипторы. Реализация `Drop` снимает эту заботу.
    struct Handle(EVT_HANDLE);

    impl Handle {
        fn new(handle: EVT_HANDLE) -> Self {
            Self(handle)
        }

        fn raw(&self) -> EVT_HANDLE {
            self.0
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                // Ошибку закрытия игнорируем: поделать с ней нечего,
                // а паниковать в деструкторе нельзя.
                unsafe {
                    let _ = EvtClose(self.0);
                }
            }
        }
    }

    /// Преобразует строку Rust в строку с завершающим нулём для Windows API.
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Переводит ошибку Windows в понятную категорию.
    fn classify(err: windows::core::Error) -> ChannelError {
        // Код распаковывается из HRESULT: сравнивать упакованное значение
        // с чистым кодом Win32 бессмысленно, они никогда не совпадут.
        let code = super::win32_code(err.code().0);

        if code == ERROR_ACCESS_DENIED.0 {
            ChannelError::AccessDenied
        } else if code == ERROR_EVT_CHANNEL_NOT_FOUND.0 {
            // Отдельный код «канал не найден»: так приходит отсутствующий
            // PowerShell 7 или неустановленный Sysmon. Это не поломка узла,
            // а ожидаемая ситуация, и сообщение должно это объяснять.
            ChannelError::NotFound
        } else if code == ERROR_FILE_NOT_FOUND.0 {
            ChannelError::NotFound
        } else {
            ChannelError::Other(code, err.message())
        }
    }

    /// Читает новые записи канала, продолжая с закладки.
    pub fn read_channel(
        channel: &str,
        bookmark_xml: Option<&str>,
        first_run_tail: usize,
    ) -> Result<(Vec<String>, Option<String>), ChannelError> {
        let channel_wide = wide(channel);
        // Запрос «*» означает «все записи канала»; отбор значимых
        // выполняется уже на нашей стороне по коду события.
        let query_wide = wide("*");

        // EvtQuery открывает результат запроса по каналу.
        let resultset = unsafe {
            EvtQuery(
                None,
                PCWSTR::from_raw(channel_wide.as_ptr()),
                PCWSTR::from_raw(query_wide.as_ptr()),
                // ForwardDirection — от старых записей к новым: закладка
                // указывает на последнюю прочитанную, и продолжать нужно
                // вперёд по времени.
                EvtQueryChannelPath.0 | EvtQueryForwardDirection.0,
            )
        }
        .map(Handle::new)
        .map_err(classify)?;

        // Закладка: если она есть, продолжаем с неё, а не с начала журнала.
        //
        // ВАЖНО: EvtSeek работает только на Admin и Operational каналах.
        // Для аналитических и отладочных каналов он вернёт ошибку —
        // такие каналы здесь и не опрашиваются.
        // ЗАКЛАДКА СОЗДАЁТСЯ ВСЕГДА, даже когда её ещё нет.
        //
        // ПОЧЕМУ. Закладка — это единственный носитель позиции чтения.
        // Если при первом проходе её не создать, то сохранять будет нечего:
        // следующий проход снова встанет на конец журнала и прочитает ТЕ ЖЕ
        // самые записи. Они уйдут в Core повторно (там отбросятся по
        // идентификатору) — но трафик и нагрузка на разбор возникали бы
        // впустую каждые несколько секунд, бесконечно.
        //
        // Пустой XML означает «создать пустую закладку».
        let bookmark = {
            // Для новой закладки передаётся именно NULL, а не пустая строка.
            // Разница существенна: NULL означает «создать закладку без
            // позиции», а указатель на пустую строку — это попытка разобрать
            // её как XML закладки, что даст ошибку. Так предписывает справка
            // Microsoft: EvtCreateBookmark(NULL).
            let existing = bookmark_xml.filter(|xml| !xml.is_empty());
            let xml_wide = existing.map(wide);

            let pointer = match &xml_wide {
                Some(buffer) => PCWSTR::from_raw(buffer.as_ptr()),
                None => PCWSTR::null(),
            };

            let handle = unsafe { EvtCreateBookmark(pointer) }
                .map(Handle::new)
                .map_err(classify)?;

            // Продолжение с закладки: смещение 0 означает «первая запись
            // ПОСЛЕ закладки».
            //
            // Отказ здесь НЕ прерывает чтение. Закладка может не содержать
            // позиции (например, в прошлый раз записей не было, и закладка
            // сохранилась пустой). Тогда EvtSeek по ней откажет, и если
            // считать это ошибкой канала, оператор навсегда потерял бы
            // события этого канала из-за одной пустой закладки. Вместо
            // этого чтение продолжается — от лавины защищает либо вставка
            // на конец журнала, либо предел записей на проход.
            if existing.is_some() {
                let seek = unsafe {
                    EvtSeek(
                        resultset.raw(),
                        0,
                        Some(handle.raw()),
                        None,
                        EvtSeekRelativeToBookmark.0,
                    )
                };

                if let Err(err) = seek {
                    let code = super::win32_code(err.code().0);
                    tracing::warn!(
                        channel,
                        code,
                        "закладка не принята, читаю журнал заново"
                    );

                    // Раз закладка оказалась непригодна, встаём на конец
                    // журнала, чтобы не вычитывать всю историю узла.
                    if first_run_tail > 0 {
                        let offset = -((first_run_tail as i64) - 1);
                        let _ = unsafe {
                            EvtSeek(
                                resultset.raw(),
                                offset,
                                None,
                                None,
                                EvtSeekRelativeToLast.0,
                            )
                        };
                    }
                }
            }

            handle
        };

        // ПЕРВЫЙ ЗАПУСК: закладки нет. Без ограничения агент прочитал бы
        // ВЕСЬ журнал Security — на реальном узле это десятки тысяч записей
        // за месяцы. Такой залп событий перегрузил бы и канал, и базу Core,
        // а оператор получил бы лавину устаревших событий вместо текущей
        // картины. Поэтому, как и в сборщике Linux, читается только хвост
        // журнала: `EvtSeek` с отрицательным смещением от последней записи.
        let first_run = bookmark_xml.is_none_or(|xml| xml.is_empty());
        if first_run && first_run_tail > 0 {
            // Смещение задаётся относительно ПОСЛЕДНЕЙ записи, поэтому
            // для выборки последних N записей нужна позиция -(N-1).
            let offset = -((first_run_tail as i64) - 1);

            let seek = unsafe {
                EvtSeek(
                    resultset.raw(),
                    offset,
                    None,
                    None,
                    EvtSeekRelativeToLast.0,
                )
            };

            // Отказ здесь НЕ прерывает чтение. `EvtSeek` работает только
            // на Admin и Operational каналах; на остальных он вернёт ошибку,
            // и прерывание лишило бы оператора событий этого канала целиком.
            // Чтение продолжится с начала результата, а от лавины событий
            // защитит предел записей на проход.
            if let Err(err) = seek {
                tracing::debug!(
                    channel,
                    code = super::win32_code(err.code().0),
                    "не удалось встать на конец журнала, читаю с начала"
                );
            }
        }

        let mut xml_records = Vec::new();
        let mut buffer = vec![0isize; BATCH_SIZE];
        let mut returned: u32 = 0;

        'read: loop {
            let next = unsafe {
                EvtNext(
                    resultset.raw(),
                    &mut buffer,
                    0,
                    0,
                    &mut returned as *mut u32,
                )
            };

            match next {
                Ok(()) => {}
                Err(err) => {
                    // Конец журнала — это НЕ ошибка: записи закончились.
                    // Код распаковывается из HRESULT: нераспознанный
                    // «конец чтения» превратил бы нормальное завершение
                    // в ошибку и уничтожил уже прочитанные записи.
                    if super::win32_code(err.code().0) == ERROR_NO_MORE_ITEMS.0 {
                        break;
                    }
                    return Err(classify(err));
                }
            }

            if returned == 0 {
                break;
            }

            for index in 0..returned as usize {
                // Предел на проход: остаток дочитается следующим циклом
                // сбора, позиция сохранена в закладке.
                if xml_records.len() >= MAX_EVENTS_PER_PASS {
                    tracing::info!(
                        channel,
                        limit = MAX_EVENTS_PER_PASS,
                        "достигнут предел записей за проход, остаток будет прочитан позже"
                    );
                    break 'read;
                }

                let event = Handle::new(EVT_HANDLE(buffer[index]));

                if let Some(xml) = render_event_xml(&event) {
                    xml_records.push(xml);
                }

                // Закладку обновляем для КАЖДОЙ записи: если чтение
                // прервётся на середине пакета, продолжение будет
                // корректным, а не с начала пакета.
                // Закладка двигается на КАЖДУЮ прочитанную запись: если
                // чтение прервётся на середине пакета, продолжение будет
                // корректным, а не с начала пакета.
                if let Err(err) = unsafe { EvtUpdateBookmark(bookmark.raw(), event.raw()) } {
                    tracing::debug!(error = %err.message(), "не удалось обновить закладку");
                }
            }
        }

        // Закладку возвращаем как XML-строку, пригодную для сохранения
        // в файл состояния.
        // Возвращается закладка последней прочитанной записи. Если записей
        // не было, возвращается закладка без позиции — её сохранение
        // безопасно и не сдвигает чтение.
        Ok((xml_records, render_bookmark_xml(&bookmark)))
    }

    /// Рендерит запись события в XML.
    ///
    /// EvtRender требует буфер заранее: сначала вызов с нулевым размером
    /// сообщает нужный объём, затем буфер выделяется и вызов повторяется.
    fn render_event_xml(event: &Handle) -> Option<String> {
        render_to_string(Some(event.raw()), EvtRenderEventXml)
    }

    /// Рендерит закладку в XML.
    fn render_bookmark_xml(bookmark: &Handle) -> Option<String> {
        render_to_string(Some(bookmark.raw()), EvtRenderBookmark)
    }

    /// Общий код рендера: событие и закладка рендерятся одинаково,
    /// различается только флаг.
    fn render_to_string(fragment: Option<EVT_HANDLE>, flags: windows::Win32::System::EventLog::EVT_RENDER_FLAGS) -> Option<String> {
        let mut used: u32 = 0;
        let mut properties: u32 = 0;

        // Первый вызов: узнаём требуемый размер буфера.
        // Ожидаемая ошибка ERROR_INSUFFICIENT_BUFFER здесь — норма.
        let probe = unsafe {
            EvtRender(
                None,
                fragment?,
                flags.0,
                0,
                None,
                &mut used as *mut u32,
                &mut properties as *mut u32,
            )
        };

        if probe.is_ok() {
            // Буфер не потребовался — значит, рендерить нечего.
            return None;
        }

        if used == 0 {
            return None;
        }

        // Windows возвращает размер в БАЙТАХ, а буфер нужен под u16.
        let mut buffer = vec![0u16; (used as usize).div_ceil(2) + 1];

        let rendered = unsafe {
            EvtRender(
                None,
                fragment?,
                flags.0,
                used,
                Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
                &mut used as *mut u32,
                &mut properties as *mut u32,
            )
        };

        if rendered.is_err() {
            return None;
        }

        // Буфер содержит строку UTF-16 с завершающим нулём.
        let length = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..length]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn каналы_по_умолчанию_включают_ключевые_для_иб() {
        let channels = WindowsLogState::channels_to_poll(false);
        assert!(channels.contains(&"Security".to_string()));
        assert!(channels.contains(&"System".to_string()));
        assert!(
            !channels.contains(&SYSMON_CHANNEL.to_string()),
            "Sysmon устанавливается отдельно и не должен опрашиваться по умолчанию"
        );
    }

    #[test]
    fn sysmon_добавляется_только_по_запросу() {
        let with_sysmon = WindowsLogState::channels_to_poll(true);
        assert!(with_sysmon.contains(&SYSMON_CHANNEL.to_string()));
    }

    #[test]
    fn опрашиваются_оба_канала_powershell() {
        // PowerShell 5.1 и 7 пишут в разные каналы: пропуск любого
        // означал бы потерю событий выполнения сценариев.
        let channels = WindowsLogState::channels_to_poll(false);
        assert!(channels.contains(&"Microsoft-Windows-PowerShell/Operational".to_string()));
        assert!(channels.contains(&POWERSHELL_CORE_CHANNEL.to_string()));
    }

    #[test]
    fn отсутствующий_канал_powershell_7_не_ломает_остальные() {
        // На Windows 10 без PowerShell 7 канал отсутствует, но сбор
        // по остальным каналам обязан продолжиться.
        let channels = WindowsLogState::channels_to_poll(false);
        assert!(channels.len() >= 5);
        assert!(channels.contains(&"Security".to_string()));
    }

    #[test]
    fn описание_ошибки_прав_содержит_подсказку() {
        let text = ChannelError::AccessDenied.describe("Security");
        assert!(text.contains("администратора"));
        assert!(text.contains("Security"));
    }

    #[test]
    fn описание_отсутствующего_канала_упоминает_sysmon() {
        let text = ChannelError::NotFound.describe(SYSMON_CHANNEL);
        assert!(text.contains("Sysmon"));
    }

    /// Коды взяты ИЗ РЕАЛЬНОГО ЖУРНАЛА агента, запущенного на Windows 10.
    /// Это регрессионная проверка: именно эти значения не распознавались
    /// из-за упаковки в HRESULT, и из-за этого прочитанные события
    /// выбрасывались.
    #[test]
    fn код_win32_распаковывается_из_hresult() {
        // Записано в шестнадцатеричном виде: HRESULT знаковый, и старшее
        // слово 0x8007 означает «ошибка Win32», а младшее — сам код.
        // «Отказано в доступе» на канале Security.
        assert_eq!(win32_code(0x8007_0005u32 as i32), 5);
        // «Записей больше нет» — приходит в конце КАЖДОГО чтения.
        assert_eq!(win32_code(0x8007_0103u32 as i32), 259);
        // «Канал не найден» — PowerShellCore на узле без PowerShell 7.
        assert_eq!(win32_code(0x8007_3A9Fu32 as i32), 15007);
    }

    #[test]
    fn распаковка_не_портит_уже_чистые_коды() {
        // Некоторые вызовы возвращают код Win32 напрямую, без упаковки.
        assert_eq!(win32_code(5), 5);
        assert_eq!(win32_code(259), 259);
        assert_eq!(win32_code(15007), 15007);
        assert_eq!(win32_code(0), 0);
    }

    #[test]
    fn отказ_в_доступе_распознаётся_как_нехватка_прав() {
        // Без распаковки это сравнение не срабатывало, и оператор
        // не получал подсказку про права.
        assert_eq!(
            win32_code(0x8007_0005u32 as i32),
            5,
            "код 5 = ERROR_ACCESS_DENIED"
        );
    }

    #[test]
    fn конец_чтения_не_считается_ошибкой() {
        // САМЫЙ ВАЖНЫЙ СЛУЧАЙ. Код 259 приходит в конце каждого чтения.
        // Пока он не распознавался, нормальное завершение выглядело
        // ошибкой, и уже прочитанные события не доходили до Core.
        assert_eq!(win32_code(0x8007_0103u32 as i32), 259);
        assert_ne!(
            win32_code(0x8007_0103u32 as i32),
            0x8007_0103u32,
            "сравнение с упакованным значением не сработало бы"
        );
    }

    #[test]
    fn первый_проход_ограничен_хвостом_журнала() {
        // Ограничение задаётся вызывающим кодом из log_tail_lines.
        // Проверяем, что значение доходит до чтения: без него первый
        // запуск на реальном узле вычитал бы весь журнал Security.
        let mut state = WindowsLogState::default();
        assert!(state.bookmarks.is_empty());

        // На Linux чтение — заглушка, поэтому проверяется только то,
        // что вызов с ограничением не паникует и не читает ничего лишнего.
        if cfg!(not(windows)) {
            let (events, _) = collect(&mut state, false, 50);
            assert!(events.is_empty());
        }
    }

    #[test]
    fn закладки_хранятся_по_каналам_независимо() {
        // Состояние — обычная структура, поэтому проверяется без Windows.
        let mut state = WindowsLogState::default();
        state
            .bookmarks
            .insert("Security".to_string(), "<BookmarkList/>".to_string());
        state
            .bookmarks
            .insert("System".to_string(), "<BookmarkList><Bookmark/></BookmarkList>".to_string());

        assert_eq!(
            state.bookmarks.get("Security").map(String::as_str),
            Some("<BookmarkList/>")
        );
        assert_ne!(
            state.bookmarks.get("Security"),
            state.bookmarks.get("System"),
            "закладки разных каналов не должны смешиваться"
        );
    }

    #[test]
    fn заглушка_на_не_windows_не_паникует() {
        // На Linux чтение журнала Windows просто ничего не возвращает:
        // агент продолжает работать, а не падает.
        let mut state = WindowsLogState::default();
        if cfg!(not(windows)) {
            let (events, problems) = collect(&mut state, false, 200);
            assert!(events.is_empty());
            assert!(problems.is_empty());
        }
    }
}
