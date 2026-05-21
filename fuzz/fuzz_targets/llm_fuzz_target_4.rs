#![no_main]
use libfuzzer_sys::fuzz_target;

use std::sync::Arc;

use aster_bigtcp::iface::{Iface, InterfaceFlags, InterfaceType, IpIface};
use bigtcp_kernel_mock::mock::Jiffies;
use bigtcp_user::mock::{MockExt, MockScheduleNextPoll, MockWithDeviceWithRxIp};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{Ipv4Address, Ipv4Cidr, Ipv4Repr, TcpControl, TcpRepr,TcpTimestampRepr
};

fn build_syn(payload: &[u8]) -> Vec<u8> {
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket,
                        TcpRepr, TcpSeqNumber};
    use smoltcp::phy::ChecksumCapabilities;

    let tcp_repr = TcpRepr {
        src_port: 12345,
        dst_port: 80,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    };

    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),
        dst_addr: Ipv4Address::new(127, 0, 0, 1),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };

    let ip_len = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();
    let mut buffer = vec![0u8; ip_len + tcp_len];

    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_len]);
        ip_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    }
    {
        let mut tcp_packet = TcpPacket::new_unchecked(&mut buffer[ip_len..]);
        tcp_repr.emit(
            &mut tcp_packet,
            &ip_repr.src_addr.into(),
            &ip_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
    }

    buffer
}

fn build_tcp_with_control(
    control: TcpControl,
    payload: &[u8],
    last_server_seq: Option<i32>,
) -> Vec<u8> {
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpPacket, TcpRepr,
                        TcpSeqNumber};
    use smoltcp::phy::ChecksumCapabilities;

    // 至少要有 8 字节给 seq + 预留空间给 data
    if payload.len() < 8 {
        return vec![];
    }

    let seq = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let data = &payload[8..];

    let use_wrong = seq % 5 == 0;

    let (seq_number, ack_number) = if use_wrong {
        let wrong_seq = TcpSeqNumber(seq.wrapping_add(500_000) as i32);
        let wrong_ack = last_server_seq.map(|s| TcpSeqNumber(s.wrapping_add(999_999)));
        (wrong_seq, wrong_ack)
    } else {
        let normal_seq = TcpSeqNumber(seq as i32);
        let normal_ack = last_server_seq.map(|s| TcpSeqNumber(s + 1));
        (normal_seq, normal_ack)
    };

    let r = payload.len() as u32;

    // 尽量保持选项“温和”，减少 smoltcp 直接 panic 的机会
    let sack_permitted = r % 10 == 0;

    let window_scale = if r % 10 == 1 {
        Some((r % 4) as u8) // 0~3，避免太极端
    } else {
        None
    };

    let max_seg_size = if r % 10 == 2 {
        let raw = 500 + (r % 1000) as u16;
        let clamped = raw.clamp(536, 1460);
        Some(clamped)
    } else {
        None
    };

    let timestamp = if r % 10 == 3 {
        Some(TcpTimestampRepr {
            tsval: (r.wrapping_mul(1234567)) as u32,
            tsecr: (r.wrapping_mul(7654321)) as u32,
        })
    } else {
        None
    };

    let mut sack_ranges = [None, None, None];
    if r % 10 == 4 {
        let base = seq;
        let start = base.wrapping_add(100);
        let end = base.wrapping_add(200);
        if start < end {
            sack_ranges[0] = Some((start, end));
        }
    }
    if r % 20 == 5 {
        let base = seq;
        let start = base.wrapping_add(300);
        let end = base.wrapping_add(400);
        if start < end {
            sack_ranges[1] = Some((start, end));
        }
    }
    if r % 30 == 6 {
        let base = seq;
        let start = base.wrapping_add(500);
        let end = base.wrapping_add(600);
        if start < end {
            sack_ranges[2] = Some((start, end));
        }
    }

    let tcp_repr = TcpRepr {
        src_port: 12345,
        dst_port: 80,
        control,
        seq_number,
        ack_number,
        window_len: 1024,
        window_scale,
        max_seg_size,
        sack_permitted,
        sack_ranges,
        timestamp,
        payload: data,
    };

    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),
        dst_addr: Ipv4Address::new(127, 0, 0, 1),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };

    let ip_len = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();
    let mut buffer = vec![0u8; ip_len + tcp_len];

    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_len]);
        ip_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    }
    {
        let mut tcp_packet = TcpPacket::new_unchecked(&mut buffer[ip_len..]);
        tcp_repr.emit(
            &mut tcp_packet,
            &ip_repr.src_addr.into(),
            &ip_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
    }

    buffer
}

fn build_ack(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::None, payload, last_server_seq)
}

fn build_fin(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::Fin, payload, last_server_seq)
}

fn build_rst(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::Rst, payload, last_server_seq)
}

fn build_data(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::Psh, payload, last_server_seq)
}

fn build_tcp_packet(ptype: u8, payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    match ptype {
        0x01 => build_syn(payload),
        0x02 => build_ack(payload, last_server_seq),
        0x03 => build_fin(payload, last_server_seq),
        0x04 => build_rst(payload, last_server_seq),
        0x05 => build_data(payload, last_server_seq),
        _ => build_syn(payload),
    }
}

// 解析 IPv4+TCP，用于从 TX 包里提取 SYN+ACK
fn parse_ipv4_tcp(pkt: &[u8]) -> Option<(Ipv4Repr, TcpRepr<'_>)> {
    use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};

    let ipv4 = Ipv4Packet::new_checked(pkt).ok()?;
    if ipv4.next_header() != IpProtocol::Tcp {
        return None;
    }

    let ip_repr = Ipv4Repr::parse(&ipv4, &ChecksumCapabilities::default()).ok()?;

    let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
    let tcp_repr = TcpRepr::parse(
        &tcp,
        &ip_repr.src_addr.into(),
        &ip_repr.dst_addr.into(),
        &ChecksumCapabilities::default(),
    )
    .ok()?;

    Some((ip_repr, tcp_repr))
}

// TLV framing
fn parse_framed_packets(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;

    while i + 2 <= data.len() {
        let ptype = data[i];
        let len = data[i + 1] as usize;
        i += 2;

        if i + len > data.len() {
            break;
        }

        let payload = &data[i..i + len];
        i += len;

        out.push((ptype, payload));
    }

    out
}

fuzz_target!(|data: &[u8]| {
    let dev = MockWithDeviceWithRxIp::new();
    let dev_handle = dev.dev.clone();

    // 1. 按“连接”切 data，稍微放宽长度上限
    let mut conns = Vec::new();
    let mut i = 0;

    while i < data.len() && conns.len() < 4 {
        let len = (data[i] as usize % 200) + 5; // 原来是 60，这里放宽一点
        let end = (i + len).min(data.len());
        conns.push(parse_framed_packets(&data[i..end]));
        i = end;
    }

    let mut extra_payloads: Vec<Vec<u8>> = Vec::new();

    // 2. 对每个“连接”的 TLV 包做一些结构变换
    for packets in &mut conns {
        if packets.is_empty() {
            continue;
        }

        let payload = packets[0].1;
        let r = payload.len() as u32;

        if r % 10 == 0 {
            packets.push((0x05, packets[0].1)); // DATA
        }

        if r % 30 == 0 {
            packets.push((0x03, packets[0].1)); // FIN
        }

        if r % 30 == 1 {
            packets.push((0x04, packets[0].1)); // RST
        }

        if r % 10 == 1 && payload.len() < 1500 {
            let mut big = Vec::from(payload);
            big.resize(1500, 0x41);
            extra_payloads.push(big);

            let ptr = extra_payloads.last().unwrap().as_ptr();
            let len = extra_payloads.last().unwrap().len();
            let big_ref: &[u8] = unsafe { std::slice::from_raw_parts(ptr, len) };

            packets.push((0x05, big_ref)); // 大 DATA
        }

        if r % 20 == 0 {
            let syn_flood_count = (r % 20) as usize;
            for _ in 0..syn_flood_count {
                packets.push((0x01, &[])); // SYN flood
            }
        }

        if r % 20 == 1 {
            let repeat = (r % 5) + 2;
            for _ in 0..repeat {
                match r % 3 {
                    0 => packets.push((0x03, packets[0].1)), // FIN
                    1 => packets.push((0x04, packets[0].1)), // RST
                    _ => packets.push((0x05, packets[0].1)), // DATA
                }
            }
        }

        if r % 13 == 0 {
            packets.reverse();
        }
    }

    // 3. iface + listener
    let iface: Arc<dyn Iface<MockExt>> = IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
        dev,
        Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
        "fuzz4".into(),
        MockScheduleNextPoll,
        InterfaceType::LOOPBACK,
        InterfaceFlags::empty(),
    );

    use aster_bigtcp::iface::BindPortConfig;
    use aster_bigtcp::socket::{RawTcpOption, TcpListener};
    use bigtcp_user::mock::MockObserver;

    let option = RawTcpOption {
        keep_alive: None,
        is_nagle_enabled: true,
    };
    let observer = MockObserver;

    let bound = match iface.bind(BindPortConfig::Specified(80)) {
        Ok(b) => b,
        Err(_) => return,
    };

    let listener = match TcpListener::<MockExt>::new_listen(bound, 16, &option, observer) {
        Ok(l) => l,
        Err((_bound, _err)) => return,
    };

    // 4. 多轮发包 + poll + 从 TX 抓 SYN+ACK 更新 last_server_seq
    let mut now = 0u64;
    let mut last_server_seq: Option<i32> = None;

    let rounds = if !data.is_empty() {
        2 + (data[0] as usize % 4) // 2~5 轮
    } else {
        3
    };

    for _round in 0..rounds {
        {
            let mut inner = dev_handle.lock().unwrap();
            for conn in &conns {
                for (ptype, payload) in conn {
                    let pkt = build_tcp_packet(*ptype, payload, last_server_seq);
                    if !pkt.is_empty() {
                        inner.inject(&pkt);
                    }
                }
            }
        }

        let per_round_iters = 50;

        for _ in 0..per_round_iters {
            iface.poll();

            let jump = now % 7 == 0;
            if jump {
                now = now.saturating_add(2000);
            } else {
                now = now.saturating_add(10);
            }
            Jiffies::set(now);

            {
                let mut guard = dev_handle.lock().unwrap();
                let txs = guard.take_tx_packets();
                drop(guard);

                for pkt in txs {
                    if let Some((_ip, tcp)) = parse_ipv4_tcp(&pkt) {
                        if tcp.control == TcpControl::Syn && tcp.ack_number.is_some() {
                            last_server_seq = Some(tcp.seq_number.0);
                        }
                    }
                }
            }

            if now > 1_000_000 {
                break;
            }
        }

        if now > 1_000_000 {
            break;
        }
    }

    listener.close();
    iface.poll();
});
