use std::{collections::HashMap, sync::{Arc, Mutex, atomic::Ordering}};
use etherparse::UdpHeader;

use crate::{stats::Stats, utils::DnsRecord};
use crate::utils::QueuePacket;
use crate::handlers::dns;

pub fn handle(packet: QueuePacket, dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>, stats: &Arc<Stats>) {

    match UdpHeader::read_from_slice(&packet.payload[..]) {
        Err(_) => todo!(),
        Ok((udp_header, udp_payload)) => {
            stats.udp.fetch_add(1, Ordering::Relaxed);
            /*println!(
                "[Thread:{}][UDP] {}:{} -> {}:{} | len: {}",
                i,
                u8_to_ipv4(ipv4_header.source),
                udp_header.source_port,
                u8_to_ipv4(ipv4_header.destination),
                udp_header.destination_port,
                ipv4_header.payload_len
            );*/

            //Check for DNS
            if udp_header.source_port == 53 || udp_header.destination_port == 53 {
                dns::handle(udp_payload, &dns_records, &stats);
            }
        },
    }
}