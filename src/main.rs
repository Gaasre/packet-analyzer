extern crate core_affinity;

mod handlers;
mod utils;
mod stats;
mod interface;
mod packet_handler;
mod config;

use core_affinity::CoreId;
use utils::{DnsRecord, QueuePacket};
use std::{collections::HashMap, fs::File, sync::{Arc, Mutex, mpsc::{self, Receiver, Sender}}};

use crate::{config::load_config, stats::Stats, utils::Files};

fn main() {
    // Init config
    let config = load_config();
    println!("{:?}", config); 

    // Init the probe struct
    let dns_records: Arc<Mutex<HashMap<DnsRecord, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let stats = Stats::new();

    let (tx, rx): (Sender<QueuePacket>, Receiver<QueuePacket>) = mpsc::channel();

    let receiver = Arc::new(Mutex::new(rx));

    // Initializing the stats thread
    let stats_thread = stats::run(&stats);

    /* 
    We will need 1 Thread for the stats,

    For each core we will need 2 main threads
    - Thread 1: reads from interface
    - Thread 2: reads from the queue
    */

    // let core_ids = core_affinity::get_core_ids().unwrap();

    // Initializing the interface reader thread
    /*let _handles_two = core_ids.into_iter().map(|_id| {
        let _interface_thread = interface::run(&config, &tx, &dns_records, &stats);

    }).collect::<Vec<_>>();*/

    let interface_thread = interface::run(&config, &tx, &dns_records, &stats);

    /*
    let handles = core_ids.into_iter().map(|id| {
        let receiver = receiver.clone();
        // Initializing the packet handler thread
        packet_handler::run(id, receiver, &dns_records, &stats)
    }).collect::<Vec<_>>();*/

    let handler_thread = packet_handler::run(&config, CoreId { id: 1 }, receiver, &dns_records, &stats);

    // Wait for the threads to finish
    stats_thread.join().unwrap();
    interface_thread.join().unwrap();
    handler_thread.join().unwrap();
    /*for handle in handles.into_iter() {
        handle.join().unwrap();
    }*/
}
