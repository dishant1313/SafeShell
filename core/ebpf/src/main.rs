#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map},
    maps::HashMap,
    programs::TracePointContext,
    helpers::bpf_send_signal,
};

#[map(name = "POLICY")]
static POLICY: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let pid = ctx.pid();
    // In real implementation we'd check against policy.
    // We send SIGKILL (9) on violation.
    if let unsafe { POLICY.get(&pid) } = Some(&1) {
        unsafe { bpf_send_signal(9) };
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
