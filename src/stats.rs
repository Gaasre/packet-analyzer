use std::{sync::{Arc, atomic::{AtomicUsize, Ordering}}, thread::{self, JoinHandle}, time::Duration};

use crate::utils::StatType;

pub struct Stats {
    pub ipv4: AtomicUsize,
    pub ipv6: AtomicUsize,
    pub tcp: AtomicUsize,
    pub udp: AtomicUsize,
    pub dns: AtomicUsize,
    pub ctx: AtomicUsize
}

pub fn run(stats: &Arc<Stats>) -> JoinHandle<()> {
    let stats = stats.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        println!(
            "ipv4: {}  ipv6: {}  tcp: {}  udp: {}  dns: {}  ctx: {}",
            stats.get_stat(StatType::IPV4),
            stats.get_stat(StatType::IPV6),
            stats.get_stat(StatType::TCP),
            stats.get_stat(StatType::UDP),
            stats.get_stat(StatType::DNS),
            stats.get_stat(StatType::CTX)
        );
        stats.reset();
    })
}

impl Stats {
    pub fn new() -> Arc<Stats> {
        Arc::new(Stats {
            ipv4: AtomicUsize::new(0),
            ipv6: AtomicUsize::new(0),
            tcp: AtomicUsize::new(0),
            udp: AtomicUsize::new(0),
            dns: AtomicUsize::new(0),
            ctx: AtomicUsize::new(0),
        })
    }

    pub fn reset(&self) {
        self.ipv4.swap(0, Ordering::Relaxed);
        self.ipv6.swap(0, Ordering::Relaxed);
        self.tcp.swap(0, Ordering::Relaxed);
        self.udp.swap(0, Ordering::Relaxed);
    }

    pub fn get_stat(&self, stat: StatType) -> usize {
        match stat {
            StatType::TCP => {
                self.tcp.load(Ordering::Relaxed)
            },
            StatType::UDP => {
                self.udp.load(Ordering::Relaxed)
            },
            StatType::DNS => {
                self.dns.load(Ordering::Relaxed)
            },
            StatType::IPV4 => {
                self.ipv4.load(Ordering::Relaxed)
            },
            StatType::IPV6 => {
                self.ipv6.load(Ordering::Relaxed)
            },
            StatType::CTX => {
                self.ctx.load(Ordering::Relaxed)
            }
        }
    }
}
