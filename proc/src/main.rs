#![feature(const_trait_impl)]

use std::fs;
use std::path::PathBuf;
use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use proc_common::Event;
use tokio::signal;
use bytes::BytesMut;
use std::collections::HashMap;
use once_cell::sync::Lazy; 

// Static mutable vectors and lazy-initialized HashMap
pub static mut SUDO_PID: Vec<u32> = Vec::new();
pub static mut PROCESS_BY_SUDO: Vec<u32> = Vec::new();
static mut FORKED_BY_SUDO_PROCESS: Lazy<HashMap<u32, Vec<u32>>> = Lazy::new(|| HashMap::new());

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    env_logger::init();

    // Load the eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/proc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/proc"
    ))?;

    // Initialize the eBPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load and attach the program
    let program: &mut TracePoint = bpf.program_mut("proc").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    // Get online CPUs and create the AsyncPerfEventArray
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events: AsyncPerfEventArray<_> = bpf.take_map("EVENTS").unwrap().try_into()?;

    // Spawn tasks for each CPU
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                // Read events from the buffer
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter().take(events.read) {
                    let event = unsafe { (buf.as_ptr() as *const Event).read_unaligned() };
                    let (process_name, ppid, _uid) = read_process_status(event.pid).unwrap_or_default();

                    // Check if process name is "sudo" and store the PID
                    if process_name == "sudo" {
                        unsafe {
                            SUDO_PID.push(event.pid);
                        }
                    }

                    // Check if the PPID is in SUDO_PID, store the PID in PROCESS_BY_SUDO
                    unsafe {
                        if SUDO_PID.contains(&ppid) {
                            PROCESS_BY_SUDO.push(event.pid);
                            info!("sudo process name: {:?} pid: {:?}", process_name, event.pid);
                        }

                        // Check if the PPID is in PROCESS_BY_SUDO, store the PID in FORKED_BY_SUDO_PROCESS
                        if PROCESS_BY_SUDO.contains(&ppid) {
                            let vec = FORKED_BY_SUDO_PROCESS.entry(ppid).or_insert_with(Vec::new);
                            vec.push(event.pid); 
                            info!("ppid: {:?} pid: {:?} process name: {:?}", ppid, event.pid, process_name); 
                        }
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}

// Read process status from /proc/<pid>/status
fn read_process_status(pid: u32) -> Option<(String, u32, u32)> {
    let status_path = PathBuf::from(format!("/proc/{}/status", pid));
    let status_content = fs::read_to_string(status_path).ok()?;

    let mut process_name = String::new();
    let mut uid = 0;
    let mut ppid = 0;

    for line in status_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "Name:" => {
                    process_name = parts[1].to_string();
                }
                "PPid:" => {
                    ppid = parts[1].parse().unwrap_or(0);
                }
                "Uid:" => {
                    uid = parts[1].parse().unwrap_or(0);
                    break;
                }
                _ => {}
            }
        }
    }

    if !process_name.is_empty() {
        Some((process_name, ppid, uid))
    } else {
        None
    }
}
