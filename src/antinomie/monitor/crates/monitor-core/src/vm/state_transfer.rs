// SPDX-License-Identifier: GPL-3.0-only
//! Saving and loading a paused VM's state (moved out of `vm`).
use super::*;

impl VmProcess {
    pub fn save_state(&self, path: &Path) -> Result<(), String> {
        if self.qmp(&serde_json::json!({"execute":"query-status"}))?["running"].as_bool()
            != Some(false)
        {
            return Err("memory capture requires paused guest execution".into());
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("snapshot memory file: {e}"))?;
        self.transfer_state(file, false)
    }
    pub fn load_state(&self, path: &Path) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            return Err("snapshot memory file must be a nonempty regular file".into());
        }
        self.transfer_state(File::open(path).map_err(|e| e.to_string())?, true)?;
        if self.qmp(&serde_json::json!({"execute":"query-status"}))?["running"].as_bool()
            != Some(false)
        {
            return Err("incoming migration unexpectedly started execution".into());
        }
        Ok(())
    }
    pub(super) fn transfer_state(&self, mut file: File, incoming: bool) -> Result<(), String> {
        let mut qmp = Qmp::connect_with(
            &self.qmp_path,
            self.waits.qmp_connect(),
            self.waits.qmp_reply(),
        )?;
        if !incoming {
            qmp.reply("{\"execute\":\"migrate-set-capabilities\",\"arguments\":{\"capabilities\":[{\"capability\":\"x-ignore-shared\",\"state\":false}]}}\n")?;
            let capabilities = qmp.reply("{\"execute\":\"query-migrate-capabilities\"}\n")?;
            if capabilities["return"]
                .as_array()
                .and_then(|values| {
                    values
                        .iter()
                        .find(|value| value["capability"].as_str() == Some("x-ignore-shared"))
                })
                .and_then(|value| value["state"].as_bool())
                != Some(false)
            {
                return Err("QEMU cannot guarantee capture of shared guest RAM".into());
            }
        }
        let (mut host, guest) = UnixStream::pair().map_err(|e| e.to_string())?;
        host.set_read_timeout(Some(self.waits.state_socket()))
            .and_then(|_| host.set_write_timeout(Some(self.waits.state_socket())))
            .map_err(|e| e.to_string())?;
        let cancel = host.try_clone().map_err(|e| e.to_string())?;
        qmp.send_fd(&guest)?;
        drop(guest);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("antinomie-vm-state".into())
            .spawn(move || {
                let result = (|| -> Result<(), String> {
                    let mut buffer = vec![0u8; 256 * 1024];
                    loop {
                        let used = if incoming {
                            file.read(&mut buffer)
                        } else {
                            host.read(&mut buffer)
                        }
                        .map_err(|e| format!("snapshot state stream read: {e}"))?;
                        if used == 0 {
                            break;
                        }
                        if incoming {
                            host.write_all(&buffer[..used])
                        } else {
                            file.write_all(&buffer[..used])
                        }
                        .map_err(|e| format!("snapshot state stream write: {e}"))?;
                    }
                    if incoming {
                        host.shutdown(std::net::Shutdown::Write)
                            .map_err(|e| e.to_string())?;
                    } else {
                        file.sync_all()
                            .map_err(|e| format!("snapshot state durability: {e}"))?;
                    }
                    Ok(())
                })();
                let _ = sender.send(result);
            })
            .map_err(|e| format!("snapshot state worker: {e}"))?;
        let result = (|| -> Result<(), String> {
            let operation = if incoming {
                "migrate-incoming"
            } else {
                "migrate"
            };
            qmp.reply(&format!(
                "{}\n",
                serde_json::json!({"execute":operation,"arguments":{"uri":"fd:antinomie-state"}})
            ))?;
            let limit = self.waits.migration();
            let deadline = std::time::Instant::now() + limit;
            let mut stream_complete = false;
            loop {
                if !stream_complete {
                    match receiver.try_recv() {
                        Ok(result) => {
                            result?;
                            stream_complete = true;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            return Err("snapshot state worker disconnected".into());
                        }
                    }
                }
                let migration = qmp.reply("{\"execute\":\"query-migrate\"}\n")?;
                match migration["return"]["status"].as_str() {
                    Some("completed") if stream_complete => return Ok(()),
                    Some("failed" | "cancelled") => {
                        return Err(format!(
                            "QEMU snapshot migration failed: {}",
                            migration["return"]
                        ));
                    }
                    _ => {}
                }
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "QEMU snapshot migration exceeded {} seconds{}",
                        limit.as_secs(),
                        self.slow_hint()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })();
        if result.is_err() {
            let _ = qmp.reply("{\"execute\":\"migrate_cancel\"}\n");
            let _ = cancel.shutdown(std::net::Shutdown::Both);
        }
        worker
            .join()
            .map_err(|_| "snapshot state worker panicked")?;
        result
    }
}
