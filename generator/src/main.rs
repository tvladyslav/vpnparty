use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

const WARCRAFT3_PORT: u16 = 6112;
const WARCRAFT3_PAYLOAD: [u8; 16] = [
    0xf7, 0x2f, 0x10, 0x00, 0x50, 0x58, 0x33, 0x57, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const TORCHLIGHT2_PORT: u16 = 4549;
const TORCHLIGHT2_PAYLOAD: [u8; 7] = [0xab, 0x84, 0x54, 0x72, 0x2c, 0x00, 0x00];

fn main() -> std::io::Result<()> {
    let wc3_dest: SocketAddr = SocketAddr::from((Ipv4Addr::BROADCAST, WARCRAFT3_PORT));
    let wc3_socket: UdpSocket =
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, WARCRAFT3_PORT)))?;
    wc3_socket.set_broadcast(true)?;

    let tl2_dest: SocketAddr = SocketAddr::from((Ipv4Addr::BROADCAST, TORCHLIGHT2_PORT));
    let tl2_socket: UdpSocket =
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, TORCHLIGHT2_PORT)))?;
    tl2_socket.set_broadcast(true)?;

    loop {
        let _wc3_bytes_sent = wc3_socket.send_to(&WARCRAFT3_PAYLOAD, wc3_dest)?;
        let _tl2_bytes_sent = tl2_socket.send_to(&TORCHLIGHT2_PAYLOAD, tl2_dest)?;
        // println!("Sent {} bytes.", _wc3_bytes_sent + _tl2_bytes_sent);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
