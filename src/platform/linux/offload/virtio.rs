use crate::{Error, Result};
use std::mem;

// see: <include/uapi/linux/virtio_net.h> virtio_net_hdr_v1

// flags
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 0x01; /* Use csum_start, csum_offset */
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 0x02; /* Csum is valid */
pub const VIRTIO_NET_HDR_F_RSC_INFO: u8 = 0x04; /* rsc info in csum_ fields */

// gso_type
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0x00; /* Not a GSO frame */
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 0x01; /* GSO frame, IPv4 TCP (TSO) */
pub const VIRTIO_NET_HDR_GSO_UDP: u8 = 0x03; /* GSO frame, IPv4 UDP (UFO) */
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 0x04; /* GSO frame, IPv6 TCP */
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 0x05; /* GSO frame, IPv4& IPv6 UDP (USO) */
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80; /* TCP has ECN set */

const VIRTIO_NET_HEADER_SIZE: usize = mem::size_of::<VirtioNetHeader>();

/// virtio_net_hdr, host(small) endian, not network(big) endian
#[repr(C)]
#[derive(Clone, Default)]
pub struct VirtioNetHeader {
    // F_NEEDS_CSUM | F_DATA_VALID | F_RSC_INFO
    pub flags: u8,
    // GSO_NONE | GSO_TCPV4 | GSO_UDP | GSO_TCPV6 | GSO_UDP_L4 | GSO_ECN
    pub gso_type: u8,
    // offset of packet data, don't trust, calculate it by yourself
    // header_len_udp = checksum_start + 8 (udp header size)
    // header_len_tcp = checksum_start + the value of length field in tcphdr (20<=len<=60)
    // the value of length field in tcphdr = DO(high 4 bits of the 12th byte in tcphdr) * 4
    pub header_len: u16,
    // the size the user program shall split the packet into
    pub gso_size: u16,
    // offset of udp/tcp header
    pub checksum_start: u16,
    // the inner offset of checksum field in udp/tcp header
    // which is to say, checksum_start + checksum_offset = actual checksum field offset
    pub checksum_offset: u16,
}

impl core::fmt::Debug for VirtioNetHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flags = match self.flags {
            VIRTIO_NET_HDR_F_NEEDS_CSUM => "VIRTIO_NET_HDR_F_NEEDS_CSUM",
            VIRTIO_NET_HDR_F_DATA_VALID => "VIRTIO_NET_HDR_F_DATA_VALID",
            VIRTIO_NET_HDR_F_RSC_INFO => "VIRTIO_NET_HDR_F_RSC_INFO",
            _ => "unknown",
        };
        let gso_type = match self.gso_type {
            VIRTIO_NET_HDR_GSO_NONE => "VIRTIO_NET_HDR_GSO_NONE",
            VIRTIO_NET_HDR_GSO_TCPV4 => "VIRTIO_NET_HDR_GSO_TCPV4",
            VIRTIO_NET_HDR_GSO_UDP => "VIRTIO_NET_HDR_GSO_UDP",
            VIRTIO_NET_HDR_GSO_TCPV6 => "VIRTIO_NET_HDR_GSO_TCPV6",
            VIRTIO_NET_HDR_GSO_UDP_L4 => "VIRTIO_NET_HDR_GSO_UDP_L4",
            VIRTIO_NET_HDR_GSO_ECN => "VIRTIO_NET_HDR_GSO_ECN",
            _ => "unknown",
        };
        f.debug_struct("VirtioNetHeader")
            .field("flags", &flags)
            .field("gso_type", &gso_type)
            .field("header_len", &self.header_len)
            .field("gso_size", &self.gso_size)
            .field("checksum_start", &self.checksum_start)
            .field("checksum_offset", &self.checksum_offset)
            .finish()
    }
}

impl VirtioNetHeader {
    pub fn size() -> usize {
        VIRTIO_NET_HEADER_SIZE
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < VIRTIO_NET_HEADER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        let hdr = &data[..VIRTIO_NET_HEADER_SIZE];
        let flags = hdr[0];
        let gso_type = hdr[1];
        let header_len = u16::from_le_bytes([hdr[2], hdr[3]]);
        let gso_size = u16::from_le_bytes([hdr[4], hdr[5]]);
        let checksum_start = u16::from_le_bytes([hdr[6], hdr[7]]);
        let checksum_offset = u16::from_le_bytes([hdr[8], hdr[9]]);
        Ok(Self {
            flags,
            gso_type,
            header_len,
            gso_size,
            checksum_start,
            checksum_offset,
        })
    }

    pub fn encode(&self) -> [u8; VIRTIO_NET_HEADER_SIZE] {
        let mut buf = [0u8; VIRTIO_NET_HEADER_SIZE];
        buf[0] = self.flags;
        buf[1] = self.gso_type;
        buf[2..4].copy_from_slice(&self.header_len.to_le_bytes());
        buf[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        buf[6..8].copy_from_slice(&self.checksum_start.to_le_bytes());
        buf[8..10].copy_from_slice(&self.checksum_offset.to_le_bytes());

        buf
    }
}
