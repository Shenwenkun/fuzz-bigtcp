#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, EthernetAddress, ArpPacket, Ipv4Packet, Ipv4Cidr, Ipv4Address,
};
use aster_bigtcp::iface::{InterfaceFlags, Iface};
use aster_bigtcp::iface::EtherIface;
use bigtcp_user::mock::{MockExt, MockScheduleNextPoll, MockWithDeviceWithRxEth};

fuzz_target!(|data: &[u8]| {
    // 构造 MockWithDeviceWithRxEth
    let driver = MockWithDeviceWithRxEth::new();
    let dev_handle = driver.dev.clone(); // 保存 Arc<Mutex<MockDeviceWithRxEth>>

    let ether_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ip_cidr = Ipv4Cidr::new(Ipv4Address::new(192,168,0,1), 24);
    let gateway = Ipv4Address::new(192,168,0,254);

    // 构造 EtherIface —— 返回 Arc<EtherIface>
    let iface: Arc<EtherIface<MockWithDeviceWithRxEth, MockExt>> = EtherIface::new(
        driver,
        ether_addr,
        ip_cidr,
        gateway,
        "fuzz_eth".to_string(),
        MockScheduleNextPoll,
        InterfaceFlags::empty(),
    );

    // 注入 fuzz 输入 —— 用 dev_handle，而不是 iface.driver
    {
        let mut dev = dev_handle.lock().unwrap();
        dev.inject(data);
    }

    // 调用 poll —— 解引用 Arc
    iface.as_ref().poll();

    // 尝试解析输入为 Ethernet 帧
    if let Ok(frame) = EthernetFrame::new_checked(data) {
        match frame.ethertype() {
            EthernetProtocol::Ipv4 => {
                let _ = Ipv4Packet::new_checked(frame.payload());
            }
            EthernetProtocol::Arp => {
                let _ = ArpPacket::new_checked(frame.payload());
            }
            _ => {}
        }
    }

    // 捕获 TX 包 —— 用 dev_handle
    {
        let mut dev = dev_handle.lock().unwrap();
        let _tx_packets = dev.take_tx_packets();
    }
});
