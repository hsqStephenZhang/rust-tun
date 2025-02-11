//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
#![feature(ip_from)]

use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{ByteOrder, NetworkEndian};
use futures::{Sink, SinkExt, StreamExt};
use log::{debug, warn};
use packet::{
    ip::{self, Protocol},
    tcp, Packet,
};
use smoltcp::wire::{Ipv6Packet, TcpPacket};
use tun::{self, Configuration, TunPacket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let mut config = Configuration::default();

    config
        .address((10, 0, 0, 9))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .name("rtun")
        .mtu(8920)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.vnet(true);
    });

    #[cfg(target_os = "windows")]
    config.platform(|config| {
        config.initialize();
    });

    let dev = tun::create_as_async(&config)?;

    let framed = dev.into_framed_vec();
    let (mut writer, mut reader) = framed.split();

    while let Some(packets) = reader.next().await {
        let pkts = packets?;
        for pkt in pkts {
            debug!("pkt: {:?}", pkt.get_bytes().len());
            match ip::Packet::new(pkt.get_bytes()) {
                Ok(ip::Packet::V4(pkt)) => {
                    let src = pkt.source();
                    let dst = pkt.destination();
                    let protocol = pkt.protocol();
                    if protocol == Protocol::Tcp {
                        let tcp_pkt = tcp::Packet::new(pkt.payload())?;
                        let sport = tcp_pkt.source();
                        let dport = tcp_pkt.destination();
                        println!("[tcp] {}:{}=>{}:{}", src, sport, dst, dport);
                    } else if protocol == Protocol::Udp {
                        let payload = pkt.payload();
                        println!("[udp] {}=>{}, length: {}", src, dst, payload.len());
                        handle_udp(&mut writer, payload, src, dst).await;
                    }
                }
                Ok(ip::Packet::V6(_)) => {
                    let pkt = pkt.get_bytes();
                    let protocol = pkt[6];
                    if protocol == 6 {
                        // tcp
                        let sport = NetworkEndian::read_u16(&pkt[40..42]);
                        let dport = NetworkEndian::read_u16(&pkt[42..44]);
                        let tcp_header = TcpPacket::new_unchecked(&pkt[40..]);
                        println!(
                            "[tcp] {:x?}:{}=>{:x?}:{}, ",
                            &pkt[8..24],
                            sport,
                            &pkt[24..40],
                            dport,
                        );
                        println!(
                            "seq: {}, ack: {}, flags: syn: {:x?}, fin: {:x?}, rst: {:x?}",
                            tcp_header.seq_number(),
                            tcp_header.ack(),
                            tcp_header.syn(),
                            tcp_header.fin(),
                            tcp_header.rst(),
                        );
                    } else if protocol == 17 {
                        // udp
                        let mut src = [0; 16];
                        let mut dst = [0; 16];
                        src.copy_from_slice(&pkt[8..24]);
                        dst.copy_from_slice(&pkt[24..40]);
                        handle_udp_v6(&mut writer, &pkt[40..], src, dst).await;
                    }
                }
                Err(err) => println!("Received an invalid packet: {:?}", err),
            }
        }
    }
    Ok(())
}

async fn handle_udp<E: std::fmt::Debug, W: Sink<TunPacket, Error = E> + std::marker::Unpin>(
    writer: &mut W,
    pkt: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
) {
    let sport = NetworkEndian::read_u16(&pkt[0..2]);
    let dport = NetworkEndian::read_u16(&pkt[2..4]);

    let resp = emit_inet4_udp_packet(dst.octets(), src.octets(), dport, sport, &pkt[8..]);
    match writer.send(TunPacket::new(resp)).await {
        Ok(_) => println!("send back to client inet4"),
        Err(e) => println!("send back to client failed: {:?}", e),
    }
}

fn emit_inet4_udp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use smoltcp::wire::Ipv4Address as Ipv4Addr;
    use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};
    let src_ip = Ipv4Addr::from_bytes(&src_ip);
    let dst_ip = Ipv4Addr::from_bytes(&dst_ip);
    // Create a buffer for the packet
    let mut buffer = vec![0u8; 20 + 8 + payload.len()]; // IPv4 header (20 bytes) + UDP header (8 bytes) + payload
    let total_len = buffer.len() as u16;

    // Construct the UDP packet
    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[20..]);
        udp_packet.set_src_port(src_port);
        udp_packet.set_dst_port(dst_port);
        udp_packet.set_len(8 + payload.len() as u16);
        udp_packet.payload_mut().copy_from_slice(payload);
        udp_packet.fill_checksum(&src_ip.into(), &dst_ip.into());
    }

    // Wrap the UDP packet in an IPv4 packet
    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer);
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_len(20);
        ipv4_packet.set_total_len(total_len);
        ipv4_packet.set_next_header(IpProtocol::Udp);
        ipv4_packet.set_src_addr(src_ip);
        ipv4_packet.set_dst_addr(dst_ip);
        ipv4_packet.fill_checksum();
    }

    buffer
}

async fn handle_udp_v6<E: std::fmt::Debug, W: Sink<TunPacket, Error = E> + std::marker::Unpin>(
    writer: &mut W,
    pkt: &[u8],
    src: [u8; 16],
    dst: [u8; 16],
) {
    let sport = NetworkEndian::read_u16(&pkt[0..2]);
    let dport = NetworkEndian::read_u16(&pkt[2..4]);
    let len = NetworkEndian::read_u16(&pkt[4..6]);
    if len as usize != pkt.len() {
        warn!("Received an invalid packet: {:?}", pkt.len());
        return;
    }

    let resp = emit_inet6_udp_packet(dst, src, dport, sport, &pkt[8..]);
    debug!("echo back to client: {:?}", resp.len());
    match writer.send(TunPacket::new(resp)).await {
        Ok(_) => println!("send back to client inet6"),
        Err(e) => println!("send back to client failed: {:?}", e),
    }
}

fn emit_inet6_udp_packet(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    use smoltcp::wire::{IpProtocol, UdpPacket};
    let src_ip = Ipv6Addr::from_octets(src_ip);
    let dst_ip = Ipv6Addr::from_octets(dst_ip);
    // Create a buffer for the packet
    let mut buffer = vec![0u8; 40 + 8 + payload.len()]; // IPv6 header (40 bytes) + UDP header (8 bytes) + payload

    println!(
        "from {:?}:{} to {:?}:{}",
        src_ip, src_port, dst_ip, dst_port
    );

    // Construct the UDP packet
    {
        let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[40..]);
        udp_packet.set_src_port(src_port);
        udp_packet.set_dst_port(dst_port);
        udp_packet.set_len(8 + payload.len() as u16);
        udp_packet.payload_mut().copy_from_slice(payload);
        udp_packet.fill_checksum(&src_ip.into(), &dst_ip.into());
    }

    // Wrap the UDP packet in an IPv6 packet
    {
        let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut buffer);
        ipv6_packet.set_version(6);
        ipv6_packet.set_payload_len(8 + payload.len() as u16);
        ipv6_packet.set_hop_limit(64);
        ipv6_packet.set_next_header(IpProtocol::Udp);
        ipv6_packet.set_src_addr(src_ip.into());
        ipv6_packet.set_dst_addr(dst_ip.into());
    }

    buffer
}
