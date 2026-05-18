use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

const WARCRAFT3_PORT: u16 = 6112;
const WARCRAFT3_PAYLOAD: [u8; 16] = [
    0xf7, 0x2f, 0x10, 0x00, 0x50, 0x58, 0x33, 0x57, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const TORCHLIGHT2_PORT: u16 = 4549;
const TORCHLIGHT2_PAYLOAD: [u8; 7] = [0xab, 0x84, 0x54, 0x72, 0x2c, 0x00, 0x00];

const WARCRAFT3_MDNS_PORT: u16 = 5353;
const WARCRAFT3_MDNS_PAYLOAD: [u8; 53] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9, 0x5f, 0x77, 0x33, 0x78, 0x70,
    0x32, 0x37, 0x32, 0x66, 0x4, 0x5f, 0x73, 0x75, 0x62, 0x9, 0x5f, 0x62, 0x6c, 0x69, 0x7a, 0x7a,
    0x61, 0x72, 0x64, 0x4, 0x5f, 0x75, 0x64, 0x70, 0x5, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x0, 0x0,
    0xc, 0x0, 0x1,
];

fn main() -> std::io::Result<()> {
    let wc3_dest: SocketAddr = SocketAddr::from((Ipv4Addr::BROADCAST, WARCRAFT3_PORT));
    let wc3_socket: UdpSocket =
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, WARCRAFT3_PORT)))?;
    wc3_socket.set_broadcast(true)?;

    let tl2_dest: SocketAddr = SocketAddr::from((Ipv4Addr::BROADCAST, TORCHLIGHT2_PORT));
    let tl2_socket: UdpSocket =
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, TORCHLIGHT2_PORT)))?;
    tl2_socket.set_broadcast(true)?;

    let mdns_dest: SocketAddr =
        SocketAddr::from((Ipv4Addr::from_octets([224, 0, 0, 251]), WARCRAFT3_MDNS_PORT));
    let mdns_socket: UdpSocket = UdpSocket::bind(SocketAddr::from((
        Ipv4Addr::UNSPECIFIED,
        0, // bonjour uses 5353, we use ephemeral to avoid collision.
    )))?;
    mdns_socket.set_multicast_ttl_v4(255)?;

    loop {
        let _wc3_bytes_sent = wc3_socket.send_to(&WARCRAFT3_PAYLOAD, wc3_dest)?;
        let _tl2_bytes_sent = tl2_socket.send_to(&TORCHLIGHT2_PAYLOAD, tl2_dest)?;
        let _mdns_bytes_sent = mdns_socket.send_to(&WARCRAFT3_MDNS_PAYLOAD, mdns_dest)?;
        // println!("Sent {} bytes.", _wc3_bytes_sent + _tl2_bytes_sent);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
