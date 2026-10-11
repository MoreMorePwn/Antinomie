// SPDX-License-Identifier: MIT
//! Inspect a process core without opening the desktop; does not execute its code.
use antinomie_monitor_core::core_dump::CoreDump;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: core-inspect CORE_FILE")?;
    let core = CoreDump::open(&path)?;
    println!("{}", serde_json::to_string_pretty(&core)?);
    for thread in &core.threads {
        if let Some(ip) = thread.register("rip") {
            match core.disassemble(ip, 64) {
                Ok(code) => println!("Thread {} RIP {ip:#x}:\n{code}", thread.tid),
                Err(error) => println!("Thread {} RIP {ip:#x}: unavailable: {error}", thread.tid),
            }
        }
    }
    Ok(())
}
