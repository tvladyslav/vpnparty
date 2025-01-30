use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::mpsc::Sender;

use crate::{e, error, debug, trace, Vpacket};

fn join_multicast_group(src_addr: &Ipv4Addr, m_addr: &Ipv4Addr, m_port: u16) -> Result<UdpSocket, String> {
    assert!(m_addr.is_multicast());
    let vpn_socket = SocketAddrV4::new(*src_addr, m_port);
    let udp_socket = e!(UdpSocket::bind(vpn_socket));
    e!(udp_socket.join_multicast_v4(m_addr, src_addr));
    debug!("Join multicast at address {:?}:{}", m_addr, m_port);
    Ok(udp_socket)
}

/// Peer discovery via multicast
pub fn run_multicast(
    direction_id: usize,
    btx: Sender<Vpacket>,
    src_ip: Ipv4Addr,
    multicast_ip: Ipv4Addr,
    multicast_port: u16
) -> Result<(), String> {
    let listener: UdpSocket = join_multicast_group(&src_ip, &multicast_ip, multicast_port)?;
    e!(listener.send_to(&[0x00, 0x00, 0x00, 0x01, 0x53, 0x75, 0x70, 0x21, 0x00, 0x00, 0x00, 0x00], SocketAddr::new(IpAddr::V4(multicast_ip), multicast_port)));

    let mut buf = [0; 100];

    // TODO: make a breaking condition
    loop {
        let (len, remote_addr) = match listener.recv_from(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                error!("Error while receiving multicast packet: {}", e);
                continue;
            }
        };

        if remote_addr.ip() == src_ip {
            debug!("Sup!");
            continue;
        }

        trace!("MMM {:?}", &buf[..len]);

        // TODO: sup! reply with cooldown mechanism

        match remote_addr.ip() {
            IpAddr::V4(remote_ipv4_addr) => e!(btx.send(Vpacket::M((direction_id, remote_ipv4_addr)))),
            IpAddr::V6(remote_ipv6_addr) => error!("Received pachet from IPv6 address {:?}", remote_ipv6_addr),
        };
    }
}
