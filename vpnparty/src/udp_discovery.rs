use std::{net::Ipv4Addr, sync::mpsc::Sender};

use crate::{e, error, debug, trace, Vpacket};



pub fn run_udping(
    direction_id: usize,
    btx: Sender<Vpacket>,
    src_ip: Ipv4Addr,
    udping_port: u16) -> Result<(), String> {
        Ok(())
}