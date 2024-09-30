mod config;

use reqwest::Error;

use crate::config::{Config,SnodeConfig};

async fn load_config(filename: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = tokio::fs::read_to_string(filename).await?;
    let config: Config = serde_yaml::from_str(&contents)?;
    Ok(config)
}

async fn fetch_snode_data(config: &SnodeConfig) -> Result<String, Error> {
    let url = format!(
        "http://[{}]:{}/seeder-peers?passwd={}",
        config.host, config.port, config.pass
    );
    
    let response = reqwest::get(&url).await?;
    let body = response.text().await?;
    Ok(body)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the configuration from a file
    let config = load_config("config.yaml").await?;
    
    // Fetch data from the snode
    let snode_data = fetch_snode_data(&config.ptest.snode).await?;
    
    println!("Snode data: {}", snode_data);
    Ok(())
}
