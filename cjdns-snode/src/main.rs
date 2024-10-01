//! CJDNS supernode
//!
//! A supernode is a replicating database of node/link information, it's collected by scanning the
//! network for peers but PLEASE DON'T ENABLE SCANNING, there is another snode scanning and you can
//! simply connect to it's socket and listen for all of the updates sent right to your door.
//!
//! Snode allows dumping of its internal state using TCP/JSON (replication socket) and it allows
//! querying to get a path between any 2 nodes given by their keys using UDP/Benc.
//!
//! # Setup
//! * Build: `$ cargo build --release`
//! * Create the config file: `$ cp config.example.json ./config.json`
//! * Start the node: `$ ../target/release/cjdns-snode`

#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use anyhow::Result;
use cjdns_util::now_sec;
use std::io::Write;

/// Program entry point.
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!("Error: {:#}", e);
    }
}

/// Main function.
async fn run() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} {} {}:{} {}",
                now_sec(),
                record.level(),
                record.file().unwrap_or("?"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();

    // Parse command line arguments
    let opts = args::parse();
    info!("Using config file '{}'", opts.config_file.display());

    // Load config file
    let config = config::load(&opts.config_file).await?;
    debug!("{:?}", config);

    // Run the application
    server::main(config, opts).await
}

/// Command-line arguments parsing.
mod args {
    use std::path::PathBuf;

    use clap::Parser;

    /// Parse command line.
    pub(super) fn parse() -> Opts {
        Opts::parse()
    }

    /// CJDNS supernode.
    #[derive(Parser)]
    #[command(version = "0.1.0", author = "The CJDNS development team")]
    pub struct Opts {
        /// Config file path
        #[arg(long = "config", default_value = "./config.json")]
        pub config_file: PathBuf,

        /// Use old implementation for `fn compute_routing_label`
        #[arg(long = "old", short = 'o')]
        pub use_old_compute_routing_label_impl: bool,
    }
}

/// Config file parsing.
mod config {
    use std::path::Path;

    use anyhow::Error;
    use serde::Deserialize;
    use tokio::fs;

    /// Load config file
    pub(super) async fn load(file_path: &Path) -> Result<Config, Error> {
        let json = fs::read(file_path)
            .await
            .map_err(|e| anyhow!("failed to load config file '{}': {}", file_path.display(), e))?;
        let config = serde_json::from_slice(&json).map_err(|e| anyhow!("failed to parse config file '{}': {}", file_path.display(), e))?;
        Ok(config)
    }

    #[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
    pub struct SeederConfig {
        pub tester_passwds: Vec<String>,
        pub nameserver_passwds: Vec<String>,
        // After this number, nolonger recommend node for peering
        pub max_connection_count: usize,
        pub share_peers_with_nameserver: usize,
    }

    #[derive(Clone, Default, PartialEq, Eq, Debug, Deserialize)]
    pub struct Config {
        #[serde(rename = "connectCjdns")]
        pub connect: bool,

        #[serde(rename = "peers")]
        pub peers: Vec<String>,

        pub seeder: SeederConfig,
    }
}

mod message;
mod pathsearch;
mod peer;
mod server;
mod utils;
mod seeder;