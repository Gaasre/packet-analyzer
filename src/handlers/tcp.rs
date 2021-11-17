use etherparse::TcpHeader;
use std::collections::btree_map::Entry;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{atomic::Ordering, Arc, Mutex},
    thread,
    time::Duration,
    u16, usize,
};

use crate::config::Config;
use crate::utils::{AppType, Files};
use crate::{
    handlers::dns,
    stats::Stats,
    utils::{DnsRecord, QueuePacket},
};

#[derive(Debug)]
pub struct TcpContext {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub len: usize,
    pub first_ts: u128,
    pub last_ts: u128,
    pub app_type: AppType,
    pub associated_dns: Vec<String> 
}

#[derive(Debug, Clone, Copy, Eq)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

impl PartialEq for Quad {
    fn eq(&self, other: &Self) -> bool {
        (self.src == other.src && self.dst == other.dst)
            || (self.src == other.dst && self.dst == other.src)
    }
}

impl Hash for Quad {
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        let src: u64 = (u32::from(self.src.0) + u32::from(self.src.1)).into();
        let dst: u64 = (u32::from(self.dst.0) + u32::from(self.dst.1)).into();
        let sum: u64 = src + dst;
        sum.hash(hasher);
    }
}

pub fn handle(
    files: &mut Files,
    config: &Config,
    connections: Arc<Mutex<HashMap<Quad, TcpContext>>>,
    packet: QueuePacket,
    dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>,
    stats: &Arc<Stats>,
) {
    match TcpHeader::read_from_slice(&packet.payload[..]) {
        Err(_) => todo!(),
        Ok((tcp_header, tcp_payload)) => {
            // Check for SYN ACK
            if tcp_header.syn && tcp_header.ack {
                let mut mut_connections = connections.lock().unwrap();
                // check if it's a new context
                if mut_connections.contains_key(&Quad {
                    src: (packet.source, tcp_header.source_port),
                    dst: (packet.destination, tcp_header.destination_port),
                }) {
                    // if the context is found, we ignore this packet
                    return;
                } else {
                    // if new context we add it
                    // first we need to find the dns associated with the ips
                    let dns_records = dns_records.clone();
                    let dns_records = dns_records.lock().unwrap();

                    let dns_results = dns::parse_dns_record(DnsRecord {
                        dtype: crate::utils::DnsRecordType::A,
                        data: packet.source.to_string()
                    }, &dns_records);

                    let mut app_type: AppType = AppType::NONE;

                    for x in &dns_results {
                        let dns_app_type = dns::dns_to_app(&x);
                        match dns_app_type {
                            Some(t) => {
                                app_type = t;
                                break;
                            },
                            None => continue,
                        }
                    }

                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis();
                    mut_connections.insert(
                        Quad {
                            src: (packet.source, tcp_header.source_port),
                            dst: (packet.destination, tcp_header.destination_port),
                        },
                        TcpContext {
                            src_ip: packet.source,
                            dst_ip: packet.destination,
                            src_port: tcp_header.source_port,
                            dst_port: tcp_header.destination_port,
                            first_ts: ts,
                            last_ts: ts,
                            len: 1,
                            app_type: app_type,
                            associated_dns: dns_results
                        },
                    );

                    println!("{:?} {:?}", packet.source, packet.destination);

                    stats.ctx.fetch_add(1, Ordering::Relaxed);
                    // Start the kill thread
                    let stats = stats.clone();
                    drop(mut_connections);
                    thread::spawn(move || loop {
                        thread::sleep(Duration::from_secs(1));
                        let mut mut_connections = connections.lock().unwrap();
                        if mut_connections.contains_key(&Quad {
                            src: (packet.source, tcp_header.source_port),
                            dst: (packet.destination, tcp_header.destination_port),
                        }) {
                            let ts = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis();
                            let ctx = mut_connections
                                .get(&Quad {
                                    src: (packet.source, tcp_header.source_port),
                                    dst: (packet.destination, tcp_header.destination_port),
                                })
                                .unwrap();

                            if ts - ctx.last_ts >= 120000 {
                                mut_connections.remove(&Quad {
                                    src: (packet.source, tcp_header.source_port),
                                    dst: (packet.destination, tcp_header.destination_port),
                                });
                                if stats.ctx.load(Ordering::Relaxed) > 0 {
                                    stats.ctx.fetch_sub(1, Ordering::Relaxed);
                                    break;
                                }
                            }
                        } else {
                            // Can't find the context, that means FIN or RST received
                            mut_connections.remove(&Quad {
                                src: (packet.source, tcp_header.source_port),
                                dst: (packet.destination, tcp_header.destination_port),
                            });
                            if stats.ctx.load(Ordering::Relaxed) > 0 {
                                stats.ctx.fetch_sub(1, Ordering::Relaxed);
                                break;
                            }
                        }
                    });
                }
            } else if (tcp_header.fin && tcp_header.ack) || tcp_header.rst {
                let mut mut_connections = connections.lock().unwrap();
                // we drop the context
                if mut_connections.contains_key(&Quad {
                    src: (packet.source, tcp_header.source_port),
                    dst: (packet.destination, tcp_header.destination_port),
                }) {
                    // if the context is found, we drop it
                    mut_connections.remove(&Quad {
                        src: (packet.source, tcp_header.source_port),
                        dst: (packet.destination, tcp_header.destination_port),
                    });
                }
            } else {
                let mut mut_connections = connections.lock().unwrap();
                // normal packet
                // here we will do all the processing
                // first we check if the context exist if not we drop the packet (or not ?)
                if !mut_connections.contains_key(&Quad {
                    src: (packet.source, tcp_header.source_port),
                    dst: (packet.destination, tcp_header.destination_port),
                }) {
                    // if the context is not found, we ignore this packet
                    return;
                } else {
                    if tcp_payload.len() <= 3 {
                        return;
                    }
                    
                    match mut_connections.get_mut(&Quad {
                        src: (packet.source, tcp_header.source_port),
                        dst: (packet.destination, tcp_header.destination_port),
                    }) {
                        Some(ctx) => {
                            ctx.len += 1;
                            ctx.last_ts = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis();
                            // handling applications
                            // Whatsapp
                            if tcp_payload[0] == 69 && tcp_payload[1] == 68 && tcp_payload[2] == 0 && tcp_payload[3] == 1 {
                                ctx.app_type = AppType::WHATSAPP;
                            }

                            if ctx.app_type == AppType::WHATSAPP {
                                println!("[0]Whatsapp packet len: {:?}", packet.payload_len);
                            }
                        },
                        None => (),
                    }
                    
                }
            }

            stats.tcp.fetch_add(1, Ordering::Relaxed);
        }
    };
}
