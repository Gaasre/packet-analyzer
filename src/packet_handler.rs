use std::{collections::HashMap, fs::File, sync::{Arc, Mutex, mpsc::{Receiver,}}, thread::{self, JoinHandle}};

use core_affinity::CoreId;
use num_traits::FromPrimitive;

use crate::{config::Config, handlers::{
        tcp::{self, Quad, TcpContext},
        udp,
    }, stats::Stats, utils::{DnsRecord, Files, ProtocolType, QueuePacket}};

pub fn run(
    config: &Config,
    core_id: CoreId,
    queue: Arc<Mutex<Receiver<QueuePacket>>>,
    dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>,
    stats: &Arc<Stats>,
) -> JoinHandle<()> {
    core_affinity::set_for_current(core_id);

    let stats = stats.clone();
    let dns_records = dns_records.clone();

    let connections: Arc<Mutex<HashMap<Quad, TcpContext>>> = Arc::new(Mutex::new(HashMap::new()));
    
    let mut files: Files = Files { whatsapp: None };

    let config = config.clone();

    let cfg = config.clone();
    // create the files
    if config.whatsapp.debug {
        match File::open(config.whatsapp.file) {
            Ok(file) => files.whatsapp = Some(file),
            Err(e) => println!("Couldn't open whatsapp debug"),
        }
    }
    

    thread::spawn(move || {
        loop {
            let queue_packet = queue.lock().unwrap().recv().unwrap();
            match FromPrimitive::from_u8(queue_packet.protocol) {
                Some(ProtocolType::TCP) => {
                    let connections = connections.clone();
                    tcp::handle(&mut files, &cfg, connections, queue_packet, &dns_records, &stats);
                },
                Some(ProtocolType::UDP) => {
                    udp::handle(queue_packet, &dns_records, &stats);
                },
                Some(ProtocolType::IGMP) => (),
                None => (),
            }
        }
    })
}
