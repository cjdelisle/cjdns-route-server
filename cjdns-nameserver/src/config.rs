use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr, SocketAddr}};

use cjdns_eth_rpc::EthRpcConfig;
use serde::{Deserialize, Serialize};

#[derive(Serialize,Deserialize)]
pub struct NameserverConfig {
    pub public_ipv4: Ipv4Addr,
    pub public_ipv6: Option<Ipv6Addr>,
    pub my_name: String,
    pub bind_ipv4: SocketAddr,
    pub bind_ipv6: Option<SocketAddr>,
    pub rpc: EthRpcConfig,
    pub nameservers: Vec<String>,
    pub special_ns_prefix: HashMap<String,String>,
}