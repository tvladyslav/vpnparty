// SPDX-FileCopyrightText: 2026 Vladyslav Tsilytskyi
// SPDX-License-Identifier: GPL-3.0-or-later

use pcap::Address;
use std::net::IpAddr;

/// Accepts zero or more ports
pub fn port_filter(ports: &[u16]) -> String {
    let filter: String = match ports.len() {
        0 => String::new(),
        1 => format!(" and (dst port {})", ports[0]),
        _ => {
            format!(
                " and ({})",
                ports
                    .iter()
                    .map(|v| format!("(dst port {})", v))
                    .collect::<Vec<_>>()
                    .join(" or ")
            )
        }
    };

    filter
}

/// At least one address must be
pub fn host_filter(addr: &[Address]) -> String {
    let addresses = addr
        .iter()
        .filter(|v| matches!(v.addr, IpAddr::V4(_)))
        .collect::<Vec<_>>();
    assert_ne!(addresses.len(), 0);
    let host_filter: String = if addresses.len() == 1 {
        format!("(src host {})", addresses[0].addr)
    } else {
        format!(
            "({})",
            addresses
                .iter()
                .map(|v| format!("(src host {})", v.addr))
                .collect::<Vec<_>>()
                .join(" or ")
        )
    };
    host_filter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_filter_test() {
        let empty_filter: String = port_filter(&[]);
        assert!(empty_filter.is_empty());

        let one_port: String = port_filter(&[8642]);
        assert_eq!(one_port, " and (dst port 8642)");

        let three_ports: String = port_filter(&[5, 76, 3578]);
        assert_eq!(
            three_ports,
            " and ((dst port 5) or (dst port 76) or (dst port 3578))"
        );
    }

    #[test]
    #[should_panic]
    fn empty_host_filter_test() {
        host_filter(&[]);
    }

    #[test]
    #[should_panic]
    fn ipv6_host_filter_test() {
        let addr1: pcap::Address = pcap::Address {
            addr: IpAddr::from([
                0xfe80, 0x4356, 0x13e1, 0x409f, 0xba86, 0xfffe, 0x4b77, 0xcba9,
            ]),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None,
        };
        host_filter(&[addr1.clone(), addr1.clone(), addr1.clone()]);
    }

    #[test]
    fn host_filter_test() {
        let addr1: Address = Address {
            addr: IpAddr::from([192, 168, 0, 11]),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None,
        };
        let one_host: String = host_filter(std::slice::from_ref(&addr1));
        assert_eq!(one_host, "(src host 192.168.0.11)");

        let addr2: pcap::Address = pcap::Address {
            addr: IpAddr::from([
                0xfe80, 0x4356, 0x13e1, 0x409f, 0xba86, 0xfffe, 0x4b77, 0xcba9,
            ]),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None,
        };
        let one_ipv4_host: String = host_filter(&[addr2.clone(), addr1.clone()]);
        assert_eq!(one_ipv4_host, "(src host 192.168.0.11)");

        let addr3: pcap::Address = pcap::Address {
            addr: IpAddr::from([10, 1, 1, 12]),
            netmask: Some(IpAddr::from([255, 255, 255, 0])),
            broadcast_addr: None,
            dst_addr: None,
        };
        let addr4: pcap::Address = pcap::Address {
            addr: IpAddr::from([172, 16, 2, 13]),
            netmask: Some(IpAddr::from([255, 255, 0, 0])),
            broadcast_addr: None,
            dst_addr: None,
        };
        let three_ipv4_hosts: String = host_filter(&[addr1, addr2, addr3, addr4]);
        assert_eq!(
            three_ipv4_hosts,
            "((src host 192.168.0.11) or (src host 10.1.1.12) or (src host 172.16.2.13))"
        );
    }
}
