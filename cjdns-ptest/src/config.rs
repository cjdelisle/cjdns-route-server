use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SnodeConfig {
    pub host: String,
    pub port: u16,
    pub pass: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CjdnsAdminConfig {
    pub host: String,
    pub port: u16,
    pub pass: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PtestConfig {
    pub retest_after_minutes: u64,
    pub parallel_tests: usize,
    pub snode: SnodeConfig,
    pub require_snode: Option<String>,
    pub cjdns_admin: CjdnsAdminConfig,
    pub http_bind: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub ptest: PtestConfig,
}
