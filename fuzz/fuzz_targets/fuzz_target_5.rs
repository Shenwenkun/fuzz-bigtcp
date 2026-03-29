#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{
    Ipv4Address, Ipv4Cidr, Ipv4Repr, Ipv4Packet,
    UdpRepr, UdpPacket, IpProtocol, IpAddress,
};
use smoltcp::phy::ChecksumCapabilities;

use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType, Iface, BindPortConfig};
use aster_bigtcp::socket::UdpSocket;
use bigtcp_user::mock::{MockWithDeviceWithRx, MockExt, MockScheduleNextPoll, MockObserver};
use bigtcp_kernel_mock::mock::Jiffies;

use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // ---- 1. 设备 + iface ----
    let dev = MockWithDeviceWithRx::new();
    let dev_handle = dev.dev.clone();

    let iface: Arc<dyn Iface<MockExt>> =
        IpIface::<MockWithDeviceWithRx, MockExt>::new(
            dev,
            Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
            "fuzz5".into(),
            MockScheduleNextPoll,
            InterfaceType::LOOPBACK,
            InterfaceFlags::empty(),
        );

    // ---- 2. 创建 UDP socket（关键步骤）----
    let bound = match iface.bind(BindPortConfig::Specified(12345)) {
        Ok(b) => b,
        Err(_) => return,
    };

    let observer = MockObserver;

    let udp_socket = match UdpSocket::<MockExt>::new_bind(bound, observer) {
        Ok(s) => s,
        Err(_) => return,
    };

    // 防止 socket 被 drop（drop 会 unregister）
    let _keep_alive = udp_socket;

    // ---- 3. 从 data 里取端口 + payload ----
    let src_port = u16::from_le_bytes([data[0], data[1]]);

    // fuzz 端口语义：提高命中 socket 的概率
    let dst_port = match data[2] % 5 {
        0 => 12345, // 命中 socket
        1 => 0,     // 非法端口
        2 => 53,    // DNS 风格
        3 => 123,   // NTP 风格
        _ => u16::from_le_bytes([data[2], data[3]]),
    };

    let payload = &data[4..];

    // ---- 4. 构造 UDP Repr ----
    let udp_repr = UdpRepr {
        src_port,
        dst_port,
    };

    let udp_header_len = udp_repr.header_len();
    let udp_total_len = udp_header_len + payload.len();

    // ---- 5. 构造 IPv4 Repr ----
    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),
        dst_addr: Ipv4Address::new(127, 0, 0, 1),
        next_header: IpProtocol::Udp,
        payload_len: udp_total_len,
        hop_limit: 64,
    };

    let ip_len = ip_repr.buffer_len();
    let total_len = ip_len + udp_total_len;

    let mut buffer = vec![0u8; total_len];

    // ---- 6. emit IPv4 ----
    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_len]);
        ip_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    }

    // ---- 7. emit UDP header + payload ----
    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[ip_len..]);

        udp_repr.emit(
            &mut udp_packet,
            &IpAddress::Ipv4(ip_repr.src_addr),
            &IpAddress::Ipv4(ip_repr.dst_addr),
            payload.len(),
            |p| p.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
    }

    // ---- 8. 篡改 len 字段（长度 fuzz）----
    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[ip_len..]);
        let real_len = udp_header_len + payload.len();

        let fuzz_len = match data[0] % 4 {
            0 => real_len,
            1 => real_len + 1000,
            2 => real_len.saturating_sub(5),
            _ => 0,
        };

        udp_packet.set_len(fuzz_len as u16);
    }

    // ---- 9. 篡改 checksum（checksum fuzz）----
    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[ip_len..]);

        match data[1] % 3 {
            0 => udp_packet.set_checksum(0),
            1 => udp_packet.set_checksum(0xFFFF),
            _ => udp_packet.set_checksum(
                u16::from_le_bytes([data[6], data[7]])
            ),
        }
    }

    // ---- 10. 多包注入 ----
    let repeat = (data[3] % 3) + 1;

    for _ in 0..repeat {
        let mut inner = dev_handle.lock().unwrap();
        inner.inject(&buffer);
    }

    // ---- 11. poll ----
    let mut now = 0u64;
    for _ in 0..50 {
        iface.poll();
        now += 10;
        Jiffies::set(now);
    }
});
