use crate::critical;

fn rewrite_ip4_checksum(buf: &mut [u8]) -> Result<(), String> {
    if buf.len() != 20 {
        return Err("Incorrect packet header length.".to_string());
    }
    buf[10] = 0u8;
    buf[11] = 0u8;
    let checksum: u16 = calculate_ip4_checksum(buf);
    buf[10] = (checksum >> 8) as u8;
    buf[11] = (checksum & 0xFF) as u8;
    Ok(())
}

fn calculate_ip4_checksum(buf: &[u8]) -> u16 {
    let sum: usize = buf
        .chunks(2)
        .map(|c| ((c[0] as usize) << 8) + (c[1] as usize))
        .sum();
    let carry: usize = sum >> 16;
    let checksum: u16 = !(((sum & 0xFFFF) + carry) as u16);
    checksum
}

#[test]
fn ip4_checksum() {
    #[rustfmt::skip]
    let input: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
        0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    let given_checksum = calculate_ip4_checksum(&input);
    let expected_checksum: u16 = 0xb861u16;
    assert_eq!(given_checksum, expected_checksum);
}

pub fn craft_udp_packet(given: &[u8], src: &[u8; 4], dst: &[u8; 4], id: Option<u16>) -> Vec<u8> {
    let mut no_ether_pktbuf: Vec<u8> = given.to_vec();

    // Rewrite Identification field if required
    if let Some(udpid) = id {
        no_ether_pktbuf[4] = (udpid >> 8) as u8;
        no_ether_pktbuf[5] = (udpid & 0xFF) as u8;
    }

    // Rewrite source and destination IPs
    no_ether_pktbuf[12..16].copy_from_slice(src);
    no_ether_pktbuf[16..20].copy_from_slice(dst);

    if rewrite_ip4_checksum(&mut no_ether_pktbuf[0..20]).is_err() {
        critical!("Should never happen! Checksum calculation error.");
    }

    //TODO: UDP checksum (optional)

    no_ether_pktbuf
}
