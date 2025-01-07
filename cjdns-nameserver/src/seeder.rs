use std::{net::SocketAddr, sync::Arc};

use base64::Engine;
use base64::prelude::BASE64_STANDARD_NO_PAD;
use eyre::{bail, OptionExt, Result, Context};
use tokio::sync::Mutex;
use rand::prelude::SliceRandom;

use cjdns_bytes::dnsseed::{CjdnsPeer, CjdnsTxtRecord};
use cjdns_keys::CJDNSPublicKey;
use cjdns_snode_wire::SeederListPeer;
use cjdns_util::now_sec;
use crate::config::SeederConfig;

#[derive(Default)]
struct SeederMut {
    peers: Vec<SeederListPeer>,
    last_update: u64,
}

pub struct Seeder {
    m: Mutex<SeederMut>,
    snode_url: String,
    snode_key: Option<CJDNSPublicKey>,
}
impl Seeder {
    pub fn new(cfg: &SeederConfig) -> Result<Arc<Self>> {
        let out = Arc::new(Self {
            snode_url: format!("http://{}:{}/seeder-peers?passwd={}",
                cfg.snode_host, cfg.snode_port, cfg.snode_pass),
            m: Default::default(),
            snode_key: if let Some(key) = &cfg.snode_key {
                Some(CJDNSPublicKey::try_from(&key[..])
                    .context("snode_key not a valid cjdns public key")?)
            } else {
                None
            },
        });
        tokio::task::spawn(Arc::clone(&out).thread());
        Ok(out)
    }
    pub async fn get_seed_txt(self: &Arc<Self>) -> Result<String> {
        // 0. If the last update is more than 5 minutes old, error.
        // 1. Take a random 3 nodes from the list of peers. We have rand as a dependency.
        // 2. Convert them through parse_list_peer, if any fails, log it and continue.
        // 3. create a CjdnsTxtRecord{ snode_pubkey: self.snode_key.map(|k|k.raw().clone()), peers: decoded_peers, peer_id: None, unknown_records: Vec::new(), }
        // 4. encode the CjdnsTxtRecord as a TXT record by calling rec.encode()?

        let m = self.m.lock().await;
        if now_sec() - m.last_update > 300 {
            bail!("Peers are too old");
        }
        let mut rng = rand::thread_rng();
        let mut decoded_peers = Vec::new();
        for _ in 0..3 {
            if let Some(peer) = m.peers.choose(&mut rng) {
                match parse_list_peer(peer) {
                    Ok(peer) => decoded_peers.push(peer),
                    Err(e) => println!("Error parsing peer: {:?}", e),
                }
            }
        }
        let rec = CjdnsTxtRecord{
            snode_pubkey: self.snode_key.as_ref().map(|k|k.raw().clone()),
            peers: decoded_peers,
            peer_id: None,
            unknown_records: Vec::new(),
        };
        Ok(rec.encode()?)
    }

    async fn update_peers(self: &Arc<Self>) -> Result<()> {
        // Get the peers from the snode, decode as an array of SeederListPeer.
        // As long as the list is not empty, update the peers and last_update.
        // In any error, just bail.
        let res = reqwest::get(&self.snode_url).await?;
        // If res is not 200, bail with the status code.
        if !res.status().is_success() {
            bail!("Getting peers from snode: HTTP status code: {}", res.status());
        }
        let peers: Vec<SeederListPeer> = res.json().await?;
        if peers.is_empty() {
            bail!("Getting peers from snode: Empty list");
        }
        let mut m = self.m.lock().await;
        m.peers = peers;
        m.last_update = now_sec();
        Ok(())
    }
    async fn thread(self: Arc<Self>) {
        loop {
            // Call self.update_peers(), in case of error, log it. In any case we sleep 1 minute.
            let res = self.update_peers().await;
            if let Err(e) = res {
                println!("Error updating peers: {:?}", e);
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    }
}

pub fn parse_list_peer(p: &SeederListPeer) -> Result<CjdnsPeer> {
     let address: SocketAddr = p.peer.address.parse().context("ip_port could not be parsed")?;
     let pubkey = CJDNSPublicKey::try_from(&p.peer.public_key[..])
        .context("pubkey not a valid cjdns public key")?;
     let login: u16 = {
        // "AP_LOGIN: 20221",
        let index_str = p.peer.login.strip_prefix("AP_LOGIN: ")
            .ok_or_eyre("login must start with AP_LOGIN: ")?;
        index_str.parse().context("index must be an unsigned number between 0 and 65535")?
     };
    let password = {
        let pass = p.peer.password.strip_prefix("AP_PASS: ")
            .ok_or_eyre("password must start with AP_PASS: ")?;
        let x = BASE64_STANDARD_NO_PAD.decode(pass)
            .and_then(|pass|{
                if pass.len() != 8 { Err(base64::DecodeError::InvalidLength) } else { Ok(pass) } 
            })
            .context("If specified --pass must be 8 bytes encoded as base64")?;
        let mut out = [0u8; 8];
        out.copy_from_slice(&x[..]);
        out
    };
    let version = p.peer.version;
    Ok(CjdnsPeer{
        address,
        pubkey: pubkey.raw().clone(),
        login,
        password,
        version,
    })
}

#[cfg(test)]
mod tests {
    use hickory_client::{rr::{rdata::TXT, Record, RecordData}, serialize::binary::BinEncodable};

    #[test]
    fn test_concat() {
        // Make sure it works to concatnate strings to make a TXT record and TXT::to_string() will output
        // the two strings concatnated.
        let three_hundred_char_string = "a".repeat(300);
        let record = Record::from_rdata(
            "test".parse().unwrap(),
            300,
            TXT::new(vec![
                three_hundred_char_string[0..255].into(),
                three_hundred_char_string[255..].into(),
            ]).into_rdata(),
        );
        // Check we CAN encode this record
        record.to_bytes().unwrap();
        let txt = record.data().unwrap().as_txt().unwrap();
        assert_eq!(txt.to_string(), three_hundred_char_string);
    }
}