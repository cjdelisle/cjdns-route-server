use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Serialize,Deserialize)]
pub struct NameserverConfig {
    pub public_ipv4: Ipv4Addr,
    pub my_name: String,
    pub bind_ipv4: SocketAddr,
    pub rpc_websockers: Vec<String>,
}