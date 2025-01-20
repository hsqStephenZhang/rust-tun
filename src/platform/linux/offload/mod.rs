use byteorder::{ByteOrder, NetworkEndian};
use bytes::BytesMut;
use checksum::partial_csum;
use log::debug;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use virtio::{VirtioNetHeader, VIRTIO_NET_HDR_F_NEEDS_CSUM};

use crate::TunPacket;

pub mod virtio;

const TCP_FLAGS_OFFSET: usize = 13;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;

/// hdr: the virtio header splited from the original buf
/// buf: the packet splited of the virtio header
pub fn handle_virtio_read(
    mut hdr: VirtioNetHeader,
    mut buf: BytesMut,
) -> std::io::Result<Vec<TunPacket>> {
    let mut packets = vec![];

    // 1. check the solidity of the hdr
    // TODO: check the solidity of the hdr

    if hdr.gso_type == virtio::VIRTIO_NET_HDR_GSO_NONE {
        if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            let csum_start = hdr.checksum_start as usize;
            let csum_offset = hdr.checksum_offset as usize;
            let init_csum = NetworkEndian::read_u16(
                &buf[csum_start + csum_offset..csum_start + csum_offset + 2],
            );
            buf[csum_start + csum_offset] = 0;
            buf[csum_start + csum_offset + 1] = 0;
            let csum = !checksum::combine(&[init_csum, checksum::data(&buf[csum_start..])]);
            NetworkEndian::write_u16(
                &mut buf[csum_start + csum_offset..csum_start + csum_offset + 2],
                csum,
            );
        }
        let packet = TunPacket::from(Into::<bytes::Bytes>::into(buf));
        return Ok(vec![packet]);
    }

    // 2. fix the header length by calculating length with tcp/udp header length
    let real_header_len = if hdr.gso_type == virtio::VIRTIO_NET_HDR_GSO_UDP_L4 {
        hdr.checksum_start + 8 // udp header length is 8
    } else if hdr.gso_type == virtio::VIRTIO_NET_HDR_GSO_TCPV4
        || hdr.gso_type == virtio::VIRTIO_NET_HDR_GSO_TCPV6
    {
        // read the length from tcp hdr field
        if buf.len() < hdr.checksum_start as usize + 12 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tcp header length is too short",
            ))?;
        }
        let tcp_hdr_length = 4 * buf[hdr.checksum_start as usize + 12] >> 4;
        if !(20..=60).contains(&tcp_hdr_length) {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tcp header lenght invalid: {}", tcp_hdr_length),
            ))?;
        }
        hdr.checksum_start + tcp_hdr_length as u16
    } else {
        unreachable!()
    };
    let protocol = if hdr.gso_type == virtio::VIRTIO_NET_HDR_GSO_UDP_L4 {
        smoltcp::wire::IpProtocol::Udp
    } else {
        smoltcp::wire::IpProtocol::Tcp
    };
    let tcp_seq = if protocol == smoltcp::wire::IpProtocol::Tcp {
        Some(NetworkEndian::read_u32(
            &buf[hdr.checksum_start as usize + 4..hdr.checksum_start as usize + 8],
        ))
    } else {
        None
    };
    hdr.header_len = real_header_len;
    let checksum_start = hdr.checksum_start as usize;
    let checksum_offset = hdr.checksum_offset as usize;
    let header_len = hdr.header_len as usize;
    let gso_size = hdr.gso_size as usize;

    let is_ipv6 = buf[0] >> 4 == 6;
    if !is_ipv6 {
        // clear checksum
        buf[10] = 0;
        buf[11] = 0;
    }

    let (src, dst) = if is_ipv6 {
        let src = Ipv6Address::from_bytes(&buf[8..24]);
        let dst = Ipv6Address::from_bytes(&buf[24..40]);
        (IpAddress::Ipv6(src), IpAddress::Ipv6(dst))
    } else {
        let src = Ipv4Address::from_bytes(&buf[12..16]);
        let dst = Ipv4Address::from_bytes(&buf[16..20]);
        (IpAddress::Ipv4(src), IpAddress::Ipv4(dst))
    };
    // 3. split payload starts from hdr.header_len by gso_size

    let packet_data_start = hdr.header_len as usize;
    let end = buf.len();
    let mut start = packet_data_start;
    let mut i = 0;
    let identification = NetworkEndian::read_u16(&buf[4..6]);
    while start < end {
        let mut new_packet = BytesMut::new();
        let mut packet_end = start + gso_size;
        let mut is_last = false;
        if packet_end > end {
            packet_end = end;
            is_last = true;
        }
        let split_payload = &buf[start..packet_end];
        let total_len = header_len + split_payload.len();
        assert!(total_len <= u16::MAX as usize);
        println!("total len: {}, start: {}", total_len, start);
        new_packet.reserve(total_len);
        new_packet.extend_from_slice(&buf[0..checksum_start]);

        // a. copy ip header, and fill i) total length ii) identification iii) checksum
        if !is_ipv6 {
            NetworkEndian::write_u16(&mut new_packet[2..4], total_len as u16);
            NetworkEndian::write_u16(&mut new_packet[4..6], identification + i as u16);

            // TODO: calculate the checksum
            let ip_checksum: u16 = checksum::data(&new_packet[..checksum_start]);
            NetworkEndian::write_u16(&mut new_packet[10..12], ip_checksum);
        } else {
            // for ipv6, we just need to set the total length
            NetworkEndian::write_u16(&mut new_packet[4..6], (total_len - checksum_start) as u16);
        }

        // b. copy tcp/udp header
        //      for udp: i) fix the total length ii) calculate the checksum
        //      for tcp: i) fix the seq number ii) fix the flag iii) calculate the checksum

        new_packet.extend(&buf[checksum_start..hdr.header_len as usize]);

        if protocol == smoltcp::wire::IpProtocol::Udp {
            NetworkEndian::write_u16(
                &mut new_packet[checksum_start + 4..checksum_start + 6],
                8 + split_payload.len() as u16,
            );
        } else if protocol == smoltcp::wire::IpProtocol::Tcp {
            // seq
            let tcp_seq_start = tcp_seq.unwrap() + i * gso_size as u32;
            NetworkEndian::write_u32(
                &mut new_packet[checksum_start + 4..checksum_start + 8],
                tcp_seq_start,
            );
            // flag
            if !is_last {
                // only the last packet has the FIN and PSH flag
                new_packet[checksum_start + TCP_FLAGS_OFFSET] &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
            }
        }
        // c. copy the payload, now all the packet is ready except the checksum in step b
        new_packet.extend(split_payload);

        // calculate the transport layer checksum: pseudo header + transport layer header + data
        let partial_csum = !partial_csum(
            &src,
            &dst,
            protocol,
            (header_len - checksum_start + split_payload.len()) as _,
            &new_packet[checksum_start..],
        );
        NetworkEndian::write_u16(
            &mut new_packet[checksum_start + checksum_offset..checksum_start + checksum_offset + 2],
            partial_csum,
        );

        start += gso_size;
        i += 1;
        log::debug!(
            "packet {:?}, length: {}, payload len: {}, header_len: {}",
            i,
            new_packet.len(),
            split_payload.len(),
            header_len
        );
        #[cfg(test)]
        verify(&new_packet);
        packets.push(new_packet.into());
    }

    Ok(packets)
}

// merging requirements: tools/testing/selftests/net/gro.c
// we donnot trust the userspace network stack's checksum
/// buf: the ip packet (with all fields filled)
pub fn handle_gro(pkt: &[u8]) -> VirtioNetHeader {
    let mut vnet_hdr = VirtioNetHeader::default();
    vnet_hdr.flags = virtio::VIRTIO_NET_HDR_F_NEEDS_CSUM;

    match pkt[0] >> 4 {
        4 => {
            handle_ipv4(&mut vnet_hdr, pkt);
        }
        6 => {
            handle_ipv6(&mut vnet_hdr, pkt);
        }
        _ => panic!(""),
    }

    debug!("after processing {:?}, packet len: {}", vnet_hdr, pkt.len());
    return vnet_hdr;

    fn handle_ipv4(hdr: &mut VirtioNetHeader, pkt: &[u8]) {
        let ip = smoltcp::wire::Ipv4Packet::new_checked(pkt);
        assert!(ip.is_ok(), "error {:?}", ip.unwrap_err());
        let ip = ip.unwrap();
        hdr.checksum_start = ip.header_len() as _;
        hdr.header_len = hdr.checksum_start;

        match ip.next_header() {
            smoltcp::wire::IpProtocol::Tcp => handle_tcp(hdr, ip.payload(), false),
            smoltcp::wire::IpProtocol::Udp => handle_udp(hdr, ip.payload()),
            _ => panic!(""),
        }
    }

    fn handle_ipv6(hdr: &mut VirtioNetHeader, pkt: &[u8]) {
        let ip = smoltcp::wire::Ipv6Packet::new_checked(pkt);
        assert!(ip.is_ok(), "error {:?}", ip.unwrap_err());
        let ip = ip.unwrap();

        hdr.checksum_start = ip.header_len() as _;
        hdr.header_len = hdr.checksum_start;

        match ip.next_header() {
            smoltcp::wire::IpProtocol::Tcp => handle_tcp(hdr, ip.payload(), true),
            smoltcp::wire::IpProtocol::Udp => handle_udp(hdr, ip.payload()),
            _ => panic!(""),
        }
    }

    fn handle_tcp(hdr: &mut VirtioNetHeader, upper: &[u8], is_v6: bool) {
        let tcp = smoltcp::wire::TcpPacket::new_checked(upper);
        assert!(tcp.is_ok(), "error {:?}", tcp.unwrap_err());
        let tcp = tcp.unwrap();
        hdr.gso_type = if is_v6 {
            virtio::VIRTIO_NET_HDR_GSO_TCPV6
        } else {
            virtio::VIRTIO_NET_HDR_GSO_TCPV4
        };
        hdr.header_len += tcp.header_len() as u16;
        hdr.checksum_offset = 16;
        hdr.gso_size = tcp.payload().len() as u16;
    }

    fn handle_udp(hdr: &mut VirtioNetHeader, pkt: &[u8]) {
        let udp = smoltcp::wire::UdpPacket::new_checked(pkt);
        if let Err(_) = udp {
            let udp = smoltcp::wire::UdpPacket::new_unchecked(pkt);
            log::debug!("buffer len: {}, udp packet len: {}", pkt.len(), udp.len());
        }
        assert!(udp.is_ok(), "error {:?}", udp.unwrap_err());
        let udp = udp.unwrap();
        hdr.gso_type = virtio::VIRTIO_NET_HDR_GSO_UDP_L4;
        hdr.header_len += 8;
        hdr.checksum_offset = 6;
        hdr.gso_size = udp.payload().len() as u16;
    }
}

#[cfg(test)]
fn verify(pkt: &[u8]) {
    match pkt[0] >> 4 {
        4 => {
            verify_ipv4(pkt);
        }
        6 => {
            verify_ipv6(pkt);
        }
        _ => panic!(""),
    }

    fn verify_ipv4(pkt: &[u8]) {
        let ip = smoltcp::wire::Ipv4Packet::new_checked(pkt);
        assert!(ip.is_ok(), "error {:?}", ip.unwrap_err());
        let ip = ip.unwrap();
        ip.verify_checksum();
        match ip.next_header() {
            smoltcp::wire::IpProtocol::Tcp => {
                verify_tcp(ip.payload(), ip.src_addr().into(), ip.dst_addr().into())
            }
            smoltcp::wire::IpProtocol::Udp => {
                verify_udp(ip.payload(), ip.src_addr().into(), ip.dst_addr().into())
            }
            _ => panic!(""),
        }
    }

    fn verify_ipv6(pkt: &[u8]) {
        let ip = smoltcp::wire::Ipv6Packet::new_checked(pkt);
        assert!(ip.is_ok(), "error {:?}", ip.unwrap_err());
        let ip = ip.unwrap();
        // ipv6 has no need of verifying checksum

        match ip.next_header() {
            smoltcp::wire::IpProtocol::Tcp => {
                verify_tcp(ip.payload(), ip.src_addr().into(), ip.dst_addr().into())
            }
            smoltcp::wire::IpProtocol::Udp => {
                verify_udp(ip.payload(), ip.src_addr().into(), ip.dst_addr().into())
            }
            _ => panic!(""),
        }
    }

    fn verify_tcp(upper: &[u8], src: IpAddress, dst: IpAddress) {
        let tcp = smoltcp::wire::TcpPacket::new_checked(upper);
        assert!(tcp.is_ok(), "error {:?}", tcp.unwrap_err());
        let tcp = tcp.unwrap();
        tcp.verify_checksum(&src, &dst);
    }

    fn verify_udp(pkt: &[u8], src: IpAddress, dst: IpAddress) {
        let udp = smoltcp::wire::UdpPacket::new_checked(pkt);
        if let Err(_) = udp {
            let udp = smoltcp::wire::UdpPacket::new_unchecked(pkt);
            log::debug!("buffer len: {}, udp packet len: {}", pkt.len(), udp.len());
        }
        assert!(udp.is_ok(), "error {:?}", udp.unwrap_err());
        let udp = udp.unwrap();
        udp.verify_checksum(&src, &dst);
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};

    const fn propagate_carries(mut word: u32) -> u16 {
        word = (word >> 16) + (word & 0xffff);
        word = (word >> 16) + (word & 0xffff);
        word as u16
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(mut data: &[u8]) -> u16 {
        let mut accum = 0;

        // For each 32-byte chunk...
        const CHUNK_SIZE: usize = 32;
        while data.len() >= CHUNK_SIZE {
            let mut d = &data[..CHUNK_SIZE];
            // ... take by 2 bytes and sum them.
            while d.len() >= 2 {
                accum += NetworkEndian::read_u16(d) as u32;
                d = &d[2..];
            }

            data = &data[CHUNK_SIZE..];
        }

        // Sum the rest that does not fit the last 32-byte chunk,
        // taking by 2 bytes.
        while data.len() >= 2 {
            accum += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }
        if let Some(&byte) = data.first() {
            accum += (byte as u32) << 8;
        }

        propagate_carries(accum)
    }

    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    pub fn pseudo_header_v4(
        src_addr: &Ipv4Address,
        dst_addr: &Ipv4Address,
        next_header: IpProtocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(src_addr.as_bytes()),
            data(dst_addr.as_bytes()),
            data(&proto_len[..]),
        ])
    }

    pub fn pseudo_header_v6(
        src_addr: &Ipv6Address,
        dst_addr: &Ipv6Address,
        next_header: IpProtocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(src_addr.as_bytes()),
            data(dst_addr.as_bytes()),
            data(&proto_len[..]),
        ])
    }

    pub fn pseudo_header(
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        next_header: IpProtocol,
        length: u32,
    ) -> u16 {
        match (src_addr, dst_addr) {
            (IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr)) => {
                pseudo_header_v4(src_addr, dst_addr, next_header, length)
            }
            (IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr)) => {
                pseudo_header_v6(src_addr, dst_addr, next_header, length)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    pub fn partial_csum(
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        next_header: IpProtocol,
        length: u32,
        header: &[u8],
    ) -> u16 {
        combine(&[
            pseudo_header(src_addr, dst_addr, next_header, length),
            data(header),
        ])
    }
}
