use std::time::Duration;
use sysinfo::System;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

mod pb {
    tonic::include_proto!("alyvion");
}

use pb::event_collector_client::EventCollectorClient;
use pb::{EventBatch, ProcessInfo};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "http://localhost:5050";
    let send_interval = Duration::from_secs(10);
    let call_timeout = Duration::from_secs(5);

    let endpoint = Endpoint::from_shared(server_addr.to_string())?
        .timeout(call_timeout)
        .connect_timeout(Duration::from_secs(5));

    let channel: Channel = endpoint.connect().await?;
    let mut client = EventCollectorClient::new(channel);

    let agent_id = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_name = if cfg!(target_os = "windows") { "windows" } else { "linux" };

    let mut sys = System::new_all();

    loop {
        sys.refresh_all();

        let processes: Vec<ProcessInfo> = sys
            .processes()
            .iter()
            .map(|(pid, proc_)| ProcessInfo {
                pid: pid.as_u32(),
                name: proc_.name().to_string_lossy().to_string(),
                exe_path: proc_
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                cpu_usage: proc_.cpu_usage() as f64,
                memory_kb: proc_.memory(),
            })
            .collect();

        let request = Request::new(EventBatch {
            agent_id: agent_id.clone(),
            os: os_name.to_string(),
            processes,
        });

        match client.send_events(request).await {
            Ok(resp) => println!("Ответ сервера: {:?}", resp.into_inner()),
            Err(e) => eprintln!("Ошибка отправки: {e}"),
        }

        tokio::time::sleep(send_interval).await;
    }
}