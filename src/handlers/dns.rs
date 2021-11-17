use std::{collections::HashMap, net::Ipv4Addr, sync::{Arc, Mutex, atomic::Ordering}};
use crate::{stats::Stats, utils::{DnsRecord, DnsRecordType, AppType}, };
use phf::phf_map;

static DNS_APPS: phf::Map<&'static str, AppType> = phf_map! {
    "g.whatsapp.net" => AppType::WHATSAPP
};

pub fn _get_ip(cname: String, dns_records: &HashMap<String, DnsRecord>) -> Ipv4Addr {
    if dns_records.contains_key(&cname) {
        let val = dns_records.get(&cname).unwrap();
        match val.dtype {
            DnsRecordType::CNAME => {
                return _get_ip(String::from(&val.data), dns_records)
            }
            DnsRecordType::A => {
                return dns_records[&cname].data.parse::<Ipv4Addr>().unwrap();
            },
        }
    } 
    return Ipv4Addr::new(0, 0, 0, 0);
}

pub fn handle(payload: &[u8], dns_records: &Arc<Mutex<HashMap<DnsRecord, String>>>, stats: &Arc<Stats>) {
    match dns_parser::Packet::parse(payload) {
        Err(e) => println!("{:?}", e),
        Ok(dns_packet) => {
            stats.dns.fetch_add(1, Ordering::Relaxed);
            let mut dns_records = dns_records.lock().unwrap();
            for record in dns_packet.answers {
                match record.data {
                    dns_parser::RData::A(data) => {
                        dns_records.insert(
                            DnsRecord {
                                data: data.0.to_string(),
                                dtype: DnsRecordType::A,
                            },
                            record.name.to_string()
                        );
                    }
                    dns_parser::RData::AAAA(_) => (),
                    dns_parser::RData::CNAME(data) => {
                        dns_records.insert(
                            DnsRecord {
                                data: data.0.to_string(),
                                dtype: DnsRecordType::CNAME,
                            },
                            record.name.to_string()
                        );
                    }
                    dns_parser::RData::MX(_) => (),
                    dns_parser::RData::NS(_) => (),
                    dns_parser::RData::PTR(_) => (),
                    dns_parser::RData::SOA(_) => (),
                    dns_parser::RData::SRV(_) => (),
                    dns_parser::RData::TXT(_) => (),
                    dns_parser::RData::Unknown(_) => (),
                }
            }
            //println!("[DNS] {:?}", getIp(String::from("www.youtube.com"), &dnsRecords));
        }
    }
}

pub fn parse_dns_record(dns_record: DnsRecord, dns_records: &HashMap<DnsRecord, String>,) -> Vec<String> {
    let mut record = dns_record;
    let mut results = Vec::new();
    while dns_records.contains_key(&record) {
        let val: String = dns_records.get(&record).unwrap().to_string();
        results.push(val.to_string());
        let new_record = DnsRecord {
            dtype: DnsRecordType::CNAME,
            data: val.to_string()
        };
        record = new_record;
    }
    results
    
}

pub fn dns_to_app(dns: &str) -> Option<AppType>{
    return DNS_APPS.get(dns).cloned();
}
