use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn, debug};
use proc_common::Event;
use tokio::signal;
use bytes::BytesMut;
use user::get_user_name;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

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
                    let user_name = get_user_name();
                    info!("PID: {} UID: {} User Name: {}", event.pid, event.uid, user_name.unwrap());

                    // if let Ok(Some(name)) = task_map.get(&pid) {
                    //     println!("PID: {} UID: {} Process Name: {}", event.pid, event.uid, name);
                    // } else {
                    //     println!("PID: {} UID: {} Process Name: <not found>", event.pid, event.uid);
                    // }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
