#![no_main]
use libfuzzer_sys::fuzz_target;

use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRxIp, MockExt, MockScheduleNextPoll};
use bigtcp_kernel_mock::mock::Jiffies;
use aster_bigtcp::iface::Iface;
use std::sync::Arc;
use smoltcp::wire::TcpTimestampRepr;
use smoltcp::wire::{Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket, IpProtocol, Ipv4Address, TcpSeqNumber, TcpControl, Ipv4Cidr};

fn build_llm_tcp_packet(
    ptype: u8,
    seq: u32,
    ack: u32,
    win: u16,
    flags: u8,
    mss: u16,
    sack_perm: bool,
    tsval: u32,
    tsecr: u32,
    sack_ranges: [Option<(u32,u32)>;3],
    payload: &[u8],
) -> Vec<u8> {
    
    use smoltcp::phy::ChecksumCapabilities;

    let control = match ptype {
        1 => TcpControl::Syn,
        2 => TcpControl::None,
        3 => TcpControl::Fin,
        4 => TcpControl::Rst,
        5 => TcpControl::Psh,
        _ => TcpControl::None,
    };

    let timestamp = Some(TcpTimestampRepr { tsval, tsecr });

    let tcp_repr = TcpRepr {
        src_port: 12345,
        dst_port: 80,
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: Some(TcpSeqNumber(ack as i32)),
        window_len: win,
        window_scale: None,
        max_seg_size: Some(mss),
        sack_permitted: sack_perm,
        sack_ranges,
        timestamp,
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

use std::panic;
fuzz_target!(|data: &[u8]| {
    let _ = panic::catch_unwind(|| {
        
        let dev = MockWithDeviceWithRxIp::new();
        let dev_handle = dev.dev.clone();

        // -------------------- 1. 解析 LLM 驱动的结构化 TCP 包 --------------------
        let mut packets = Vec::new();
        let mut i = 0;

        while i + 49 <= data.len() {
            let ptype = data[i];
            let seq = u32::from_le_bytes(data[i+1..i+5].try_into().unwrap());
            let ack = u32::from_le_bytes(data[i+5..i+9].try_into().unwrap());
            let win = u16::from_le_bytes(data[i+9..i+11].try_into().unwrap());
            let flags = data[i+11];
            let mss = u16::from_le_bytes(data[i+12..i+14].try_into().unwrap());
            let sack_perm = data[i+14] % 2 == 1;

            let tsval = u32::from_le_bytes(data[i+15..i+19].try_into().unwrap());
            let tsecr = u32::from_le_bytes(data[i+19..i+23].try_into().unwrap());

            let mut sack_ranges = [None, None, None];
            for r in 0..3 {
                let start = u32::from_le_bytes(data[i+23+r*8..i+27+r*8].try_into().unwrap());
                let end   = u32::from_le_bytes(data[i+27+r*8..i+31+r*8].try_into().unwrap());
                if start < end {
                    sack_ranges[r] = Some((start, end));
                }
            }

            let payload_len = u16::from_le_bytes(data[i+47..i+49].try_into().unwrap()) as usize;
            i += 49;

            if i + payload_len > data.len() {
                break;
            }

            let payload = &data[i..i+payload_len];
            i += payload_len;

            packets.push((ptype, seq, ack, win, flags, mss, sack_perm, tsval, tsecr, sack_ranges, payload));
        }

        // -------------------- 2. 构造 iface + listener（保持不变） --------------------
        let iface: Arc<dyn Iface<MockExt>> =
            IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
                dev,
                Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
                "fuzz_llm".into(),
                MockScheduleNextPoll,
                InterfaceType::LOOPBACK,
                InterfaceFlags::empty(),
            );

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
            Err(_) => return,
        };

        // -------------------- 3. 多轮 poll + 注入（保持不变） --------------------
        let mut now = 0u64;

        for _round in 0..3 {
            {
                let mut inner = dev_handle.lock().unwrap();
                for (ptype, seq, ack, win, flags, mss, sack_perm, tsval, tsecr, sack_ranges, payload) in &packets {
                    let pkt = build_llm_tcp_packet(
                        *ptype, *seq, *ack, *win, *flags, *mss,
                        *sack_perm, *tsval, *tsecr, *sack_ranges, payload
                    );
                    if !pkt.is_empty() {
                        inner.inject(&pkt);
                    }
                }
            }

            for _ in 0..50 {
                iface.poll();
                now += 10;
                Jiffies::set(now);
            }
        }

        listener.close();
        iface.poll();
    
    });
});

