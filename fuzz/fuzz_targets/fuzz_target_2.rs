#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRx, MockExt,MockScheduleNextPoll};
use aster_bigtcp::iface::Iface;


fuzz_target!(|data: &[u8]| {
    let dev = MockWithDeviceWithRx::new();

    // 注入 fuzz 输入
    dev.dev.lock().unwrap().inject(data);

    let iface = IpIface::<MockWithDeviceWithRx, MockExt>::new(
        dev,
        Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
        "fuzz".into(),
        MockScheduleNextPoll,
        InterfaceType::LOOPBACK,
        InterfaceFlags::empty(),
    );

    iface.poll();
});
