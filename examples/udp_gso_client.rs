use clap::{arg, command, Parser};
use std::{
    io,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
};

/// example size
const MSS: usize = 1472;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "false")]
    tcp: bool,

    #[arg(short, long, default_value = "0.0.0.0:8388")]
    bind: String,

    #[arg(short, long, default_value = "1.0.0.1")]
    addr: String,

    #[arg(short, long, default_value = "80")]
    port: u16,

    /// for udp, if connect before send
    #[arg(short, long, default_value = "true")]
    connect: bool,

    // for udp, if use gso
    #[arg(short, long)]
    gso: bool,

    #[arg(short, long, help = "number of seconds to run")]
    time: u64,

    #[arg(long, default_value = "true", help = "enable audit")]
    audit: bool,
}

impl Args {
    fn remote(&self) -> (IpAddr, u16) {
        (self.addr.parse().unwrap(), self.port)
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    run(args).await?;
    Ok(())
}

enum TcpOrUdp {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

async fn run(args: Args) -> io::Result<()> {
    let mut tcp_or_udp = if args.tcp {
        TcpOrUdp::Tcp(TcpStream::connect(args.remote()).await?)
    } else {
        TcpOrUdp::Udp({
            let socket = UdpSocket::bind(&args.bind).await?;
            if args.connect {
                socket.connect(&args.remote()).await?;
            }
            set_udp_gso(&socket)?;
            set_ip_discovery(&socket)?;
            socket
        })
    };

    let interrupted = Arc::new(AtomicBool::new(false));
    let num_msgs = Arc::new(AtomicU64::new(0));
    let num_sends = Arc::new(AtomicU64::new(0));
    let total_num_msgs = num_msgs.clone();
    let total_num_sends = num_sends.clone();

    let buf = [0u8; 1472 * 42];
    let payload_len = buf.len();

    let begin_time = Instant::now();
    let mut prev_time = begin_time;
    let mut report_time = Instant::now() + Duration::from_secs(1);

    loop {
        if interrupted.load(Ordering::Relaxed) {
            break;
        }

        match tcp_or_udp {
            TcpOrUdp::Tcp(ref mut tcp_stream) => {
                run_tcp(tcp_stream, &buf).await?;
            }
            TcpOrUdp::Udp(ref mut udp_socket) => {
                run_udp(udp_socket, &buf, &args).await?;
            }
        }

        num_sends.fetch_add(1, Ordering::Relaxed);
        num_msgs.fetch_add(1, Ordering::Relaxed);

        let now = Instant::now();
        if now >= report_time {
            let elapsed = now - prev_time;
            let msgs = num_msgs.load(Ordering::Relaxed);
            let sends = num_sends.load(Ordering::Relaxed);

            println!(
                "udp tx: {:6.2} MB/s {:8} calls/s {:6} msg/s",
                (msgs * payload_len as u64) as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0,
                sends as f64 / elapsed.as_secs_f64(),
                msgs as f64 / elapsed.as_secs_f64()
            );
            if args.audit {
                total_num_msgs.fetch_add(msgs, Ordering::Relaxed);
                total_num_sends.fetch_add(sends, Ordering::Relaxed);
            }

            prev_time = now;
            num_msgs.store(0, Ordering::Relaxed);
            num_sends.store(0, Ordering::Relaxed);
            report_time = now + Duration::from_secs(1);
        }

        if now - begin_time >= Duration::from_secs(args.time) {
            break;
        }
    }

    if args.audit {
        let now = Instant::now();
        let msgs = total_num_msgs.load(Ordering::Relaxed);
        let sends = total_num_sends.load(Ordering::Relaxed);
        let elapsed = now - begin_time;
        println!(
            "udp tx: {:6.2} MB/s {:8} calls/s {:6} msg/s",
            (msgs * payload_len as u64) as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0,
            sends as f64 / elapsed.as_secs_f64(),
            msgs as f64 / elapsed.as_secs_f64()
        );
    }
    Ok(())
}

async fn run_tcp(stream: &mut TcpStream, buf: &[u8]) -> io::Result<usize> {
    stream.write_all(&buf).await?;
    // let _ = stream.read_exact()
    Ok(buf.len())
}

async fn run_udp(udp_socket: &mut UdpSocket, buf: &[u8], args: &Args) -> io::Result<usize> {
    if args.gso {
        let len = udp_socket.send(&buf[..]).await?;
        return Ok(len);
    } else {
        let chunks = buf.chunks(MSS);
        let mut sent_total = 0;
        for chunk in chunks {
            let sent = if args.connect {
                udp_socket.send(chunk).await?
            } else {
                udp_socket.send_to(chunk, args.remote()).await?
            };
            sent_total += sent;
        }
        Ok(sent_total)
    }
}

fn set_udp_gso(socket: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    const GSO_SIZE: libc::c_int = 1500;
    set_socket_option(socket, libc::SOL_UDP, libc::UDP_SEGMENT, GSO_SIZE)
}

fn set_ip_discovery(socket: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    const IP_DISCOVER: libc::c_int = 21;
    set_socket_option(socket, libc::IPPROTO_IP, IP_DISCOVER, 2)
}

fn set_socket_option(
    socket: &impl std::os::fd::AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const _,
            std::mem::size_of_val(&value) as _,
        )
    };
    match rc == 0 {
        true => Ok(()),
        false => Err(std::io::Error::last_os_error()),
    }
}
