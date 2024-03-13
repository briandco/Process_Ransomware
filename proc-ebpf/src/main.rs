#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint}, maps::PerfEventArray, programs::TracePointContext, EbpfContext, PtRegs
};
use aya_log_ebpf::info;
use proc_common::Event;

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[tracepoint]
pub fn proc(ctx: TracePointContext) -> u32 {
    match try_proc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_proc(ctx: TracePointContext) -> Result<u32, u32> {
    let data = Event{
        pid: ctx.pid(),
        uid: ctx.uid(),
    };
    unsafe { EVENTS.output(&ctx, &data, 0) };
    
    //info!(&ctx, "tracepoint sched_process_exec called for {} and uid is {}",ctx.pid(), ctx.uid());
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
