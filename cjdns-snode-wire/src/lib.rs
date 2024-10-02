use std::net::SocketAddr;

use cjdns_bytes::dnsseed::PeeringLine;
use serde::{Deserialize, Serialize};

#[derive(Serialize,Deserialize,Clone)]
pub struct SeederTestResNode {
    pub addr: SocketAddr,
    pub ip6: String,
    pub error: Option<String>,
}

#[derive(Serialize,Deserialize,Clone)]
pub struct SeederTestRes {
    pub passwd: String,
    pub nodes: Vec<SeederTestResNode>,
}

#[derive(Serialize,Deserialize,Clone)]
pub struct SeederListPeer {
    pub last_check_sec: u64,
    pub last_report_sec: u64,
    pub ring: u32,
    pub check_error: Option<String>,
    pub peer: PeeringLine,
    pub id: String,
}