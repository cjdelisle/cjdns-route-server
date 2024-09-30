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
    pub retest_after_minutes: u32,
    pub parallel_tests: u32,
    pub snode: SnodeConfig,
    pub cjdns_admin: CjdnsAdminConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub ptest: PtestConfig,
}
