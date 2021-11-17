use std::{collections::HashMap, net::Ipv4Addr, sync::{Arc, Mutex, atomic::Ordering, mpsc::Sender}, thread::{self, JoinHandle}};

use etherparse::{Ethernet2Header, IpHeader, Ipv4Header};
use pcap::{Capture};

use crate::{
    config::Config,
    stats::Stats,
    utils::{DnsRecord, QueuePacket},
};

pub fn run(
    config: &Config,
    queue: &Sender<QueuePacket>,
    dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>,
    stats: &Arc<Stats>,
) -> JoinHandle<()> {
    if config.general.mode == "interface" {
        run_interface(config, queue, dns_records, stats)
    } else {
        run_file(config, queue, dns_records, stats)
    }
}

fn run_interface(
    config: &Config,
    queue: &Sender<QueuePacket>,
    dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>,
    stats: &Arc<Stats>,
) -> JoinHandle<()> {
    let mut cap = Capture::from_device(config.general.interface.as_str())
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();
    let queue = queue.clone();
    let stats = stats.clone();
    let _dns_records = dns_records.clone();

    thread::spawn(move || {
        while let Ok(packet) = cap.next() {
            // Parse the Ethernet and IP header
            match Ethernet2Header::read_from_slice(packet.data) {
                Err(value) => println!("Err {:?}", value),
                Ok((_, eth_payload)) => match IpHeader::read_from_slice(eth_payload) {
                    Err(_) => (),
                    Ok((ip_header, _)) => match ip_header {
                        IpHeader::Version4(_) => {
                            stats.ipv4.fetch_add(1, Ordering::Relaxed);
                            match Ipv4Header::read_from_slice(eth_payload) {
                                Err(value) => println!("Err {:?}", value),
                                Ok((ipv4_header, payload)) => {
                                    // Push to the queue
                                    match queue.send(QueuePacket {
                                        protocol: ipv4_header.protocol,
                                        source: Ipv4Addr::from(ipv4_header.source),
                                        destination: Ipv4Addr::from(ipv4_header.destination),
                                        payload_len: ipv4_header.payload_len,
                                        payload: payload.to_vec(),
                                    }) {
                                        Ok(_) => (),
                                        Err(err) => println!("{}", err),
                                    }
                                }
                            }
                        }
                        IpHeader::Version6(_) => {
                            stats.udp.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                },
            }
        }
    })
}

fn run_file(
    config: &Config,
    queue: &Sender<QueuePacket>,
    dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>,
    stats: &Arc<Stats>,
) -> JoinHandle<()> {
    let mut cap = Capture::from_file(config.general.file.as_str()).unwrap();

    let queue = queue.clone();
    let stats = stats.clone();
    let _dns_records = dns_records.clone();

    thread::spawn(move || {
        while let Ok(packet) = cap.next() {
            // Parse the Ethernet and IP header
            match Ethernet2Header::read_from_slice(packet.data) {
                Err(value) => println!("Err {:?}", value),
                Ok((_, eth_payload)) => match IpHeader::read_from_slice(eth_payload) {
                    Err(_) => (),
                    Ok((ip_header, _)) => match ip_header {
                        IpHeader::Version4(_) => {
                            stats.ipv4.fetch_add(1, Ordering::Relaxed);
                            match Ipv4Header::read_from_slice(eth_payload) {
                                Err(value) => println!("Err {:?}", value),
                                Ok((ipv4_header, payload)) => {
                                    // Push to the queue
                                    match queue.send(QueuePacket {
                                        protocol: ipv4_header.protocol,
                                        source: Ipv4Addr::from(ipv4_header.source),
                                        destination: Ipv4Addr::from(ipv4_header.destination),
                                        payload_len: ipv4_header.payload_len,
                                        payload: payload.to_vec(),
                                    }) {
                                        Ok(_) => (),
                                        Err(err) => println!("{}", err),
                                    }
                                }
                            }
                        }
                        IpHeader::Version6(_) => {
                            stats.udp.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                },
            }
        }
    })
}
