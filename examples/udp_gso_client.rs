use clap::{arg, command, Parser, ValueEnum};
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(value_enum)]
    mode: Mode,

    #[arg(short, long, default_value = "0.0.0.0:8388")]
    bind: String,

    #[arg(short, long, default_value = "1.0.0.1:54")]
    remote: String,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Mode {
    Tcp,
    Udp,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    match args.mode {
        Mode::Tcp => run_tcp(&args).await,
        Mode::Udp => run_udp(&args).await,
    }
}

async fn run_tcp(args: &Args) -> io::Result<()> {
    // Connect to remote
    let mut stream = TcpStream::connect(&args.remote).await?;

    let mut buf = [0; 1500 * 5];
    for i in 0..5 {
        let start = i * 1500;
        let end = start + 1500;
        buf[start..end].copy_from_slice(&[i as u8 + 1; 1500]);
    }

    let len = stream.write_all(&buf).await?;
    println!("{:?} bytes sent", len);

    for i in 0..5 {
        let mut chunk = vec![0; 1500];
        stream.read_exact(&mut chunk).await?;
        println!("{:?} bytes received", chunk.len());
        assert_eq!(&chunk[..], &[i as u8 + 1; 1500]);
    }

    println!("TCP done");
    Ok(())
}

async fn run_udp(args: &Args) -> io::Result<()> {
    let sock = UdpSocket::bind(&args.bind).await?;
    set_udp_gso(&sock)?;
    set_ip_discovery(&sock)?;

    let mut buf = [0; 1500 * 5];
    for i in 0..5 {
        let start = i * 1500;
        let end = start + 1500;
        buf[start..end].copy_from_slice(&[i as u8 + 1; 1500]);
    }

    let len = sock.send_to(&buf[..], &args.remote).await?;
    println!("{:?} bytes sent", len);

    for i in 0..5 {
        let (len, remote) = sock.recv_from(&mut buf[..]).await?;
        println!("{:?} bytes received from {:?}", len, remote);
        assert_eq!(len, 1500);
        assert_eq!(&buf[..len], &[i as u8 + 1; 1500]);
    }

    println!("UDP done");
    Ok(())
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
