use std::{convert::TryFrom, sync::Arc};

use anyhow::Result;
use cjdns_snode_wire::{SeederListPeer, SeederTestRes};
use cjdns_util::now_sec;
use tokio::sync::Mutex;
use rand::Rng;

use crate::config::Config;
use cjdns_bytes::{dnsseed::{CjdnsPeer, CjdnsTxtRecord, PeerID}, message::Message};
use cjdns_keys::{PublicKey, CJDNS_IP6};

const NUM_PEERS_TO_RESPOND: usize = 6;

struct SeederPeer {
    ip: CJDNS_IP6,
    peer_id: PeerID,
    creds: CjdnsPeer,
    ring: u32,
    check_error: Option<String>,
    private: bool,
    last_check_sec: u64,
    last_report_sec: u64,
}

pub trait PeerInfoProvider: Clone {
    /// Get the peer count for a node, also optionally find out if a given reference peer is
    /// one of the peers of this node.
    fn peer_info(&self, node: &CJDNS_IP6, reference_peer: Option<&CJDNS_IP6>) -> (usize, bool);
}

#[derive(Default)]
struct SeederMut {
    peers: Vec<SeederPeer>,
    top_ring: u32,
}

impl From<&SeederPeer> for SeederListPeer {
    fn from(x: &SeederPeer) -> Self {
        Self {
            last_check_sec: x.last_check_sec,
            last_report_sec: x.last_report_sec,
            ring: x.ring,
            check_error: x.check_error.clone(),
            peer: x.creds.peering_line(),
            id: x.peer_id.to_string(),
        }
    }
}

pub struct Seeder {
    m: Mutex<SeederMut>,
    config: Arc<Config>,
}
impl Seeder {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config, m: Default::default() }
    }
    fn is_appropriate(&self, peer: &CJDNS_IP6, asker: Option<&CJDNS_IP6>, pip: impl PeerInfoProvider) -> bool {
        if let Some(asker) = asker {
            if asker == peer {
                return false;
            }
        }
        let (count, is_peer_of) = pip.peer_info(peer, asker);
        !is_peer_of && count < self.config.seeder.max_connection_count
    }
    async fn handle_cred(
        &self,
        sender: &CJDNS_IP6,
        peer_id: PeerID,
        creds: CjdnsPeer,
        pip: impl PeerInfoProvider,
        out: &mut Vec<CjdnsPeer>,
    ) -> Result<()> {
        let pk = PublicKey::from(creds.pubkey);
        let ip6 = CJDNS_IP6::try_from(&pk)?;
        if ip6 != *sender {
            bail!("IPv6 of peer data does not match sender");
        }

        // Find the relevant peer and update it (or insert)
        // then find 4 ellegable peers to give to them:
        // 1 peer in the lowest ring above theirs (or above, or any)
        // 3 peers in their ring (or above, or any)
        let now_s = now_sec();
        let is_ipv6 = creds.address.is_ipv6();

        let mut m = self.m.lock().await;
        let ring = if let Some(ent) = m.peers.iter_mut()
            .find(|p|p.ip == *sender && p.creds == creds)
        {
            if ent.peer_id != peer_id || creds != creds {
                ent.peer_id = peer_id;
                ent.creds = creds;
                ent.check_error = None;
                ent.last_check_sec = 0;
            }
            ent.last_report_sec = now_s;
            ent.ring
        } else {
            let ring = m.top_ring;
            m.peers.push(SeederPeer{
                private: !peer_id.id.starts_with(b"PUB_"),
                peer_id,
                ip: sender.clone(),
                creds,
                ring,
                check_error: None,
                last_check_sec: 0,
                last_report_sec: now_s,
            });
            ring
        };

        let mut added_peers = 0;
        let mut attempt = if out.is_empty() { 0 } else { 1 };
        loop {
            if attempt > 4 {
                return Ok(());
            }
            for peer in &m.peers {
                if added_peers >= NUM_PEERS_TO_RESPOND {
                    return Ok(());
                }
                if attempt == 4 {
                    return Ok(());
                } else if attempt == 3 {
                    // Try every single node
                } else if attempt == 2 && peer.ring >= ring {
                    // Try all BETTER nodes
                } else if attempt == 1 && peer.ring == ring {
                    // Try same ring nodes, except first node
                } else if attempt == 0 && peer.ring + 1 == ring {
                    // Try to get ONE node which populates
                } else {
                    continue;
                }
                if peer.private {
                    continue;
                }
                if peer.creds.address.is_ipv6() != is_ipv6 {
                    continue;
                }
                if out.contains(&peer.creds) {
                    continue;
                }
                if self.is_appropriate(&peer.ip, Some(sender), pip.clone()) {
                    added_peers += 1;
                    out.push(peer.creds.clone());
                    if attempt == 0 {
                        // in attempt 0, we're only adding a single node.
                        break;
                    }
                }
            }
            attempt += 1;
        }
    }
    pub async fn post_credentials(
        &self,
        sender: &CJDNS_IP6,
        bin_creds: &[u8],
        pip: impl PeerInfoProvider,
    ) -> Result<Vec<u8>> {
        let rec = CjdnsTxtRecord::decode_bin(bin_creds)?;
        let CjdnsTxtRecord{ peer_id, peers, .. } = rec;
        let peer_id = match peer_id {
            Some(pid) => pid,
            None => bail!("Credential post missing peer ID"),
        };
        let mut selections = Vec::new();
        for peer in peers {
            self.handle_cred(sender, peer_id.clone(), peer, pip.clone(), &mut selections).await?;
        }
        let mut rng = rand::thread_rng();
        while selections.len() > NUM_PEERS_TO_RESPOND {
            // Remove random peers from the list, NEVER remove the first entry because it's "better"
            let loser = rng.gen_range(1, selections.len());
            selections.remove(loser);
        }
        let mut msg = Message::new();
        CjdnsTxtRecord{
            peers: selections,
            ..Default::default()
        }.encode_bin(&mut msg)?;
        Ok(msg.as_vec())
    }
    pub async fn list_peers(
        &self,
        passwd: &String,
        pip: impl PeerInfoProvider,
    ) -> Result<Vec<SeederListPeer>> {
        if self.config.seeder.tester_passwds.contains(passwd) {
            return Ok(self.m.lock().await.peers.iter().map(|p|p.into()).collect());
        } else if !self.config.seeder.nameserver_passwds.contains(passwd) {
            bail!("Unknown password");
        }
        let last_check_cutoff = now_sec() - 60*60;
        // Get the number worst working peers to give to the nameserver
        let m = self.m.lock().await;
        let mut ok_peers = m.peers.iter().enumerate()
            .filter(|(_,p)|{
                !p.private &&
                p.check_error.is_none() &&
                p.last_check_sec > last_check_cutoff
            })
            .map(|(i,p)|(i,p.ring))
            .collect::<Vec<_>>();
        ok_peers.sort_by_key(|(_,r)|u32::MAX - r);
        let mut out = Vec::with_capacity(self.config.seeder.share_peers_with_nameserver);
        for (i, _) in ok_peers {
            let p = &m.peers[i];
            if self.is_appropriate(&p.ip, None, pip.clone()) {
                out.push(p.into());
                if out.len() >= self.config.seeder.share_peers_with_nameserver {
                    break;
                }
            }
        }
        Ok(out)
    }
    pub async fn testres(
        &self,
        res: SeederTestRes,
    ) -> Result<()> {
        if !self.config.seeder.tester_passwds.contains(&res.passwd) {
            bail!("Unknown password");
        }
        let now_s = now_sec();
        let mut m = self.m.lock().await;
        for p in res.nodes {
            let ip6 = CJDNS_IP6::try_from(&p.ip6[..])?;
            if let Some(sp) = m.peers.iter_mut()
                .find(|sp|sp.creds.address == p.addr && sp.ip == ip6)
            {
                sp.check_error = p.error;
                sp.last_check_sec = now_s;
            }
        }
        Ok(())
    }
}

// 4,8,12,16
// xxx+0 -> 8 peers
// xxxxxx+01 -> 64 peers
// xxxxxxxxx+011 -> 512 peers
// xxxxxxxxxxxxx+111 -> 8192 peers