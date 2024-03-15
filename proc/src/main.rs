#![feature(const_trait_impl)]
use std::fs;
use std::path::PathBuf;

use aya::maps::{AsyncPerfEventArray};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn, debug};
use proc_common::Event;
use tokio::signal;
use bytes::BytesMut;
use user::get_user_name;
use std::collections::HashMap;
use once_cell::sync::Lazy; 

pub static  mut sudo_pid: Vec<u32> = Vec::new();
pub static mut process_by_sudo: Vec<u32> = Vec::new();
// Use Lazy to initialize the HashMap lazily
static mut FORKED_BY_SUDO_PROCESS: Lazy<HashMap<u32, Vec<u32>>> = Lazy::new(|| HashMap::new());



#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // // new memcg based accounting, see https://lwn.net/Articles/837122/
    // let rlim = libc::rlimit {
    //     rlim_cur: libc::RLIM_INFINITY,
    //     rlim_max: libc::RLIM_INFINITY,
    // };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    // if ret != 0 {
    //     debug!("remove limit on locked memory failed, ret is: {}", ret);
    // }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/proc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/proc"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut TracePoint = bpf.program_mut("proc").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events: AsyncPerfEventArray<_> = bpf.take_map("EVENTS").unwrap().try_into()?;

    
   
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();
            // println!("outside loop");
            loop {
                // println!("inside loop");
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter().take(events.read) {
                    // println!("inside for loop");
                    let event = unsafe { (buf.as_ptr() as *const Event).read_unaligned() };
                    let (process_name,ppid, uid) = read_process_status(event.pid).unwrap_or_default();
                    info!("PID: {} PPID: {} UID {} Process Name: {}", event.pid, ppid, uid, process_name);                    
                    // Check if process name is "sudo" and store the PID
                    if process_name == "sudo"
                    {
                        unsafe {
                            
                            sudo_pid.push(event.pid);
                        }
                    }
                    // Check if the PPID is in sudo_pids, store the PID in hashmap
                    unsafe{
                    if sudo_pid.contains(&ppid){
                        process_by_sudo.push(event.pid);
                        
                    }
                   
                    if process_by_sudo.contains(&ppid){
                        // FORKED_BY_SUDO_PROCESS.get_mut(&ppid).unwrap().entry(ppid).or_insert_with(Vec::new).push(event.pid);
                        let vec = FORKED_BY_SUDO_PROCESS.entry(ppid).or_insert_with(Vec::new);
                            vec.push(event.pid);
                    }

                }
                
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    unsafe{
     // Print the PIDs of processes with the name "sudo"
     info!("PIDs of processes with name 'sudo': {:?}", sudo_pid);
     // Print the PPID to PIDs hashmap
     info!("PPID to PIDs: {:?}", process_by_sudo);
     info!("Forked by 'sudo' process mapping: {:?}", *FORKED_BY_SUDO_PROCESS);
    }
    Ok(())
}

fn read_process_status(pid: u32) -> Option<(String, u32, u32)> {
    let status_path = PathBuf::from(format!("/proc/{}/status",pid));
    let status_content = fs::read_to_string(status_path).ok()?;

    let mut process_name = String::new();
    let mut uid = 0;
    let mut ppid = 0;

    for line in status_content.lines(){
        let parts:Vec<&str> =line.split_whitespace().collect();
        if parts.len() >= 2{
            match parts[0]{
                "Name:" =>{
                    process_name = parts[1].to_string();
                }
                "PPid:" =>{
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
    }else{
        None
    }
   
}
