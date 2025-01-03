use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr, SocketAddr}};

use cjdns_eth_rpc::EthRpcConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SeederConfig {
    pub snode_host: String,
    pub snode_port: u16,
    pub snode_pass: String,
    pub snode_key: Option<String>,
}

#[derive(Serialize,Deserialize)]
pub struct NameserverConfig {
    pub public_ipv4: Ipv4Addr,
    pub public_ipv6: Option<Ipv6Addr>,
    pub my_name: String,
    pub bind_ipv4: SocketAddr,
    pub bind_ipv6: Option<SocketAddr>,
    pub rpc: EthRpcConfig,
    pub nameservers: Vec<(String,String)>,
    pub special_ns_prefix: HashMap<String,String>,
    pub seeder: Option<SeederConfig>,
}