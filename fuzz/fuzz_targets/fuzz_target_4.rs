#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRx, MockExt, MockScheduleNextPoll};
use bigtcp_kernel_mock::mock::Jiffies;
use aster_bigtcp::iface::Iface;
use std::sync::Arc;
use smoltcp::wire::TcpTimestampRepr;

// -------------------- TCP 构造器 --------------------
use smoltcp::wire::{TcpControl, Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket, IpProtocol, TcpSeqNumber};
use smoltcp::phy::ChecksumCapabilities;

fn build_syn(payload: &[u8]) -> Vec<u8> {
    use smoltcp::wire::{
        Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket,
        IpProtocol, TcpControl, Ipv4Address, TcpSeqNumber,
    };
    use smoltcp::phy::ChecksumCapabilities;

    // ---- TCP header ----
    let tcp_repr = TcpRepr {
        src_port: 12345,
        dst_port: 80,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,

        // 你的版本新增字段（必须全部填）
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,

        payload,
    };

    // ---- IPv4 header ----
    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),   // 随便一个同网段地址
        dst_addr: Ipv4Address::new(127, 0, 0, 1),   // 必须等于 iface 绑定的地址
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };

    let ip_len = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();

    let mut buffer = vec![0u8; ip_len + tcp_len];

    // ---- emit IPv4 header ----
    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_len]);
        ip_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    }

    // ---- emit TCP header ----
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
    use smoltcp::wire::{
        Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket,
        IpProtocol, Ipv4Address, TcpSeqNumber,
    };
    use smoltcp::phy::ChecksumCapabilities;

    if payload.len() < 8 {
        return vec![];
    }

    let seq = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    // let ack = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let data = &payload[8..];

    let use_wrong = seq % 5 == 0;

    let (seq_number, ack_number) = if use_wrong {
        // 错误 seq/ack → 触发重传
        let wrong_seq = TcpSeqNumber(seq.wrapping_add(500_000) as i32);
        let wrong_ack = last_server_seq.map(|s| TcpSeqNumber(s.wrapping_add(999_999)));
        (wrong_seq, wrong_ack)
    } else {
        // 正常 seq/ack → 走正常路径
        let normal_seq = TcpSeqNumber(seq as i32);
        let normal_ack = last_server_seq.map(|s| TcpSeqNumber(s + 1));
        (normal_seq, normal_ack)
    };

    // ---- 阶段 5：SACK / timestamp / window_scale fuzzing ----
    let r = payload.len() as u32;

    // 10% 概率启用 SACK permitted
    let sack_permitted = r % 10 == 0;

    // 10% 概率启用 window scale
    let window_scale = if r % 10 == 1 {
        Some((r % 8) as u8)   // window scale 0~7
    } else {
        None
    };

    // 10% 概率 fuzz MSS
    let max_seg_size = if r % 10 == 2 {
        Some(500 + (r % 1000) as u16)   // 500~1500
    } else {
        None
    };

    // 10% 概率 fuzz timestamp
    let timestamp = if r % 10 == 3 {
        Some(TcpTimestampRepr {
            tsval: (r * 1234567) as u32,
            tsecr: (r * 7654321) as u32,
        })
    } else {
        None
    };

    // 10% 概率 fuzz SACK ranges（最多 3 个）
    let mut sack_ranges = [None, None, None];
    if r % 10 == 4 {
        let base = seq as u32;
        sack_ranges[0] = Some((base.wrapping_add(100), base.wrapping_add(200)));
    }
    if r % 20 == 5 {
        let base = seq as u32;
        sack_ranges[1] = Some((base.wrapping_add(300), base.wrapping_add(400)));
    }
    if r % 30 == 6 {
        let base = seq as u32;
        sack_ranges[2] = Some((base.wrapping_add(500), base.wrapping_add(600)));
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
        _    => build_syn(payload),
    }
}



// -------------------- 解析 IPv4+TCP，用于从 TX 包里提取 SYN+ACK --------------------
fn parse_ipv4_tcp(pkt: &[u8]) -> Option<(Ipv4Repr, TcpRepr<'_>)> {
    use smoltcp::wire::{Ipv4Packet, TcpPacket, IpProtocol};

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
    ).ok()?;

    Some((ip_repr, tcp_repr))
}



// -------------------- TLV framing --------------------
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
    let dev = MockWithDeviceWithRx::new();
    let dev_handle = dev.dev.clone();   // Arc<Mutex<MockDeviceWithRx>>

    let mut conns = Vec::new();
    let mut i = 0;

    // 最多 3 个连接（太多会压死正常路径）
    while i < data.len() && conns.len() < 3 {
        let len = (data[i] as usize % 40) + 5; // 每个连接最多 40 bytes
        let end = (i + len).min(data.len());
        conns.push(parse_framed_packets(&data[i..end]));
        i = end;
    }

    let mut extra_payloads: Vec<Vec<u8>> = Vec::new();


    for packets in &mut conns {
        if packets.is_empty() {
            continue;
        }

        let payload = packets[0].1;
        let r = payload.len() as u32;

        // ---- DATA 注入（10%）----
        if r % 10 == 0 {
            packets.push((0x05, packets[0].1));
        }

        // ---- FIN 注入（3%）----
        if r % 30 == 0 {
            packets.push((0x03, packets[0].1));
        }

        // ---- RST 注入（3%）----
        if r % 30 == 1 {
            packets.push((0x04, packets[0].1));
        }

        // ---- 大 payload 注入（10%）----
        if r % 10 == 1 && payload.len() < 1500 {
            let mut big = Vec::from(payload);
            big.resize(1500, 0x41);
            extra_payloads.push(big);
            // 关键：用 raw pointer 避免 borrow checker 冲突
            let ptr = extra_payloads.last().unwrap().as_ptr();
            let len = extra_payloads.last().unwrap().len();

            // 现在 big_ref 不再借用 extra_payloads，而是独立的 slice
            let big_ref: &[u8] = unsafe { std::slice::from_raw_parts(ptr, len) };

            packets.push((0x05, big_ref));
        }

        if r % 20 == 0 {
            let syn_flood_count = (r % 20) as usize; // 0~19 个额外 SYN
            for _ in 0..syn_flood_count {
                packets.push((0x01, &[])); // 0x01 = SYN
            }
        }

        // ---- 阶段 8：多次 FIN/RST/错误 seq 交错 ----
        // 5% 概率触发 deep state fuzzing
        if r % 20 == 1 {
            let repeat = (r % 5) + 2; // 重复 2~6 次

            for _ in 0..repeat {
                // 多次 FIN
                if r % 3 == 0 {
                    packets.push((0x03, packets[0].1));
                }

                // 多次 RST
                if r % 3 == 1 {
                    packets.push((0x04, packets[0].1));
                }

                // 多次 DATA（可能触发窗口滑动）
                if r % 3 == 2 {
                    packets.push((0x05, packets[0].1));
                }
            }
        }
    }


    let mut last_server_seq: Option<i32> = None;


    {
        let mut inner = dev.dev.lock().unwrap();
        for conn in &conns {

            for (ptype, payload) in conn {
                let pkt = build_tcp_packet(*ptype, payload, last_server_seq);
                inner.inject(&pkt);
            }
        }

    }

    let iface: Arc<dyn Iface<MockExt>> =
        IpIface::<MockWithDeviceWithRx, MockExt>::new(
            dev,
            Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
            "fuzz4".into(),
            MockScheduleNextPoll,
            InterfaceType::LOOPBACK,
            InterfaceFlags::empty(),
        );

    // 键：创建 TCP listener
    
    use aster_bigtcp::socket::TcpListener;
    use aster_bigtcp::iface::BindPortConfig;
    use aster_bigtcp::socket::RawTcpOption;
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

    

    let mut now = 0u64;

    


    for _ in 0..200 {
        iface.poll();
        let jump = now % 7 == 0; // 大约 1/7 概率
        if jump {
            now += 2000; // 触发 RTO
        } else {
            now += 10;   // 正常时间推进
        }
        Jiffies::set(now);

        // 从 TX 捕获 SYN+ACK，更新 last_server_seq
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
    
    listener.close();

    iface.poll();

    drop(listener);
});
