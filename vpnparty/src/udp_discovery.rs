use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::Sender;
use crate::{e, error, debug, Vpacket, SUP, SUP_LEN, SUP_REPLY};

/// Send Sup! packet to IP range 255.255.255.0
fn udping(socket: &UdpSocket, ip: Ipv4Addr, port: u16) -> Result<(), String> {
    let mut ip_oct: [u8; 4] = ip.octets();
    let self_d = ip_oct[3];
    for d in 0..255 {
        if d == self_d {
            continue;
        }
        ip_oct[3] = d;
        let dst_socket_addr = SocketAddr::from((ip_oct, port));
        e!(socket.send_to(&SUP, dst_socket_addr));
    }
    Ok(())
}

pub fn run_udping(
    direction_id: usize,
    btx: Sender<Vpacket>,
    src_ip: Ipv4Addr,
    udping_port: u16
) -> Result<(), String> {
    let socket_addr: SocketAddr = SocketAddr::new(IpAddr::V4(src_ip), udping_port);
    let udp_socket: UdpSocket = e!(UdpSocket::bind(socket_addr));

    e!(udping(&udp_socket, src_ip, udping_port));

    let mut buf = [0; 100];

    loop {
        let (len, remote_addr) = match udp_socket.recv_from(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                if e.kind() == io::ErrorKind::ConnectionReset {
                    // Happens :(
                    continue;
                }
                error!("Error while receiving UDP packet: {}", e);
                continue;
            }
        };

        let buddy_ip: IpAddr = remote_addr.ip();

        if buddy_ip == src_ip {
            debug!("Sup from {}!", src_ip);
            continue;
        }

        // trace!("UUU {:?}", &buf[..len]);

        if len == SUP_LEN && buf[0..SUP_LEN] == SUP {
            // Greetings to the newcommer.
            if let Err(e) = udp_socket.send_to(&SUP_REPLY, remote_addr) {
                error!("Greeting the {} buddy failed: {}", buddy_ip, e);
            }
        }

        match buddy_ip {
            IpAddr::V4(remote_ipv4_addr) => e!(btx.send(Vpacket::U((direction_id, remote_ipv4_addr)))),
            IpAddr::V6(remote_ipv6_addr) => error!("Received packet from IPv6 address {}", remote_ipv6_addr),
        };
    }
    // TODO: close UDP socket
}