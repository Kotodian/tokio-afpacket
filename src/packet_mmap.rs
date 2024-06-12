use nix::libc;
use std::ffi::{c_int, c_uint, c_ulong};
use std::num::NonZeroUsize;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::NonNull;

use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockProtocol, SockType};
use std::task::ready;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, ReadBuf};

const ETH_P_ALL: u16 = 0x0003;
const BLOCK_SIZE: usize = 4096;
const BLOCK_NR: usize = 64;
const FRAME_SIZE: usize = 256;

const PACKET_RX_RING: c_int = 5;
const PACKET_STATISTICS: c_int = 6;
const PACKET_VERSION: c_int = 10;
const PACKET_FANOUT: c_int = 18;

pub const PACKET_FANOUT_HASH: c_int = 0;
pub const PACKET_FANOUT_LB: c_int = 1;

const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;
const PACKET_OTHERHOST: u8 = 3;
const PACKET_OUTGOING: u8 = 4;

const TP_STATUS_KERNEL: u8 = 0;
const TP_STATUS_USER: u8 = 1;
//const TP_STATUS_COPY: u8 = 1 << 1;
//const TP_STATUS_LOSING: u8 = 1 << 2;
//const TP_STATUS_CSUMNOTREADY: u8 = 1 << 3;
//const TP_STATUS_CSUM_VALID: u8 = 1 << 7;

const TPACKET_V3: c_int = 2;

const SIOCGIFFLAGS: c_ulong = 35091; //0x00008913;
const SIOCSIFFLAGS: c_ulong = 35092; //0x00008914;

const IFNAMESIZE: usize = 16;
const IFREQUNIONSIZE: usize = 24;

const TP_FT_REQ_FILL_RXHASH: c_uint = 1; //0x1;

const TP_BLK_STATUS_OFFSET: usize = 8;

#[repr(C)]
#[derive(Clone, Debug)]
///Lower-level settings about ring buffer allocation and behavior
///tp_frame_size * tp_frame_nr must equal tp_block_size * tp_block_nr
pub struct TpacketReq3 {
    ///Block size of ring
    pub tp_block_size: c_uint,
    ///Number of blocks allocated for ring
    pub tp_block_nr: c_uint,
    ///Frame size of ring
    pub tp_frame_size: c_uint,
    ///Number of frames in ring
    pub tp_frame_nr: c_uint,
    ///Timeout in milliseconds
    pub tp_retire_blk_tov: c_uint,
    ///Offset to private data area
    pub tp_sizeof_priv: c_uint,
    ///Controls whether RXHASH is filled - 0 for false, 1 for true
    pub tp_feature_req_word: c_uint,
}

impl Default for TpacketReq3 {
    fn default() -> TpacketReq3 {
        TpacketReq3 {
            tp_block_size: 32768,
            tp_block_nr: 10000,
            tp_frame_size: 2048,
            tp_frame_nr: 160000,
            tp_retire_blk_tov: 100,
            tp_sizeof_priv: 0,
            tp_feature_req_word: TP_FT_REQ_FILL_RXHASH,
        }
    }
}

#[derive(Clone, Debug)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    hdr: TpacketBDHeader,
}

#[derive(Clone, Debug)]
struct TpacketBDHeader {
    block_status: u32,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64,
    ts_first_pkt: TpacketBDTS,
    ts_last_pkt: TpacketBDTS,
}

#[derive(Clone, Debug)]
struct TpacketBDTS {
    ts_sec: u32,
    ts_nsec: u32,
}

///Contains details about individual packets in a block
#[derive(Clone, Debug)]
pub struct Tpacket3Hdr {
    tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: TpacketHdrVariant1,
    //pub tp_padding: [u8; 8],
}

///Contains VLAN tags and RX Hash value (if enabled)
#[derive(Clone, Debug)]
pub struct TpacketHdrVariant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    tp_padding: u16,
}

struct PacketMmap {
    fd: AsyncFd<RawFd>,
    mmap_ptr: *mut libc::c_void,
    mmap_size: usize,
}

impl PacketMmap {
    fn new(iface: &str) -> Self {
        let sock = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::EthAll,
        )
        .unwrap();

        let mut req = TpacketReq3::default();
        let fd = sock.as_raw_fd();

        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_VERSION,
                &mut TPACKET_V3 as *mut _ as *mut libc::c_void,
                std::mem::size_of_val(&TPACKET_V3) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                std::mem::size_of::<TpacketReq3>() as u32,
            )
        };

        let mmap_size = BLOCK_SIZE * BLOCK_NR;
        let mmap_ptr = unsafe {
            mmap(
                None,
                NonZeroUsize::new_unchecked(mmap_size),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_SHARED,
                sock,
                0,
            )
            .unwrap()
        };

        PacketMmap {
            fd: AsyncFd::new(fd).expect("Failed to create AsyncFd"),
            mmap_ptr: mmap_ptr.as_ptr(),
            mmap_size,
        }
    }
}

impl AsyncRead for PacketMmap {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut guard = ready!(self.fd.poll_read_ready(cx))?;

        let hdr = unsafe { &*(self.mmap_ptr as *const Tpacket3Hdr) };
        if hdr.tp_status & TP_STATUS_USER as u32 != 0 {
            let data_ptr = unsafe { (self.mmap_ptr as *const u8).add(hdr.tp_mac as usize) };
            let data_slice =
                unsafe { std::slice::from_raw_parts(data_ptr, hdr.tp_snaplen as usize) };
            buf.put_slice(data_slice);

            let hdr = unsafe { &mut *(self.mmap_ptr as *mut Tpacket3Hdr) };
            hdr.tp_status = TP_STATUS_KERNEL as u32;

            guard.clear_ready();
            Poll::Ready(Ok(()))
        } else {
            guard.clear_ready();
            Poll::Pending
        }
    }
}

impl Drop for PacketMmap {
    fn drop(&mut self) {
        unsafe {
            munmap(NonNull::new(self.mmap_ptr).unwrap(), self.mmap_size)
                .expect("Failed to unmap memory");
            let fd = self.fd.as_raw_fd();
            libc::close(fd);
        }
    }
}
