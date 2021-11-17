use std::{fs::File, net::Ipv4Addr};

use num_derive::FromPrimitive; 

#[derive(FromPrimitive)]
pub enum ProtocolType {
    IGMP = 2,
    TCP = 6,
    UDP = 17,
}

pub enum StatType {
    IPV4,
    IPV6,
    TCP,
    UDP,
    DNS,
    CTX
}

#[derive(Debug, Clone)]
pub struct QueuePacket {
    pub protocol: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub payload_len: u16,
    pub payload: Vec<u8>
}

#[derive(PartialEq, Debug, Hash, Clone, Copy)]
pub enum DnsRecordType {
    A = 1,
    CNAME = 2,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppType {
    NONE,
    WHATSAPP
}

#[derive(Debug, Hash)]
pub struct DnsRecord {
    pub data: String,
    pub dtype: DnsRecordType
}
impl PartialEq for DnsRecord {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.dtype == other.dtype
    }
}
impl Eq for DnsRecord {}

#[derive(Debug, Default)]
pub struct Files {
    pub whatsapp: Option<File>,
}

pub fn _u8_to_ipv4(arr: [u8; 4]) -> String {
    let mut i = 0;
    let mut ip = String::from("");
    while i < arr.len() {
        ip.push_str(&arr[i].to_string());
        if i < arr.len() - 1 {
            ip.push('.')
        }
        i += 1;
    }
    ip
}