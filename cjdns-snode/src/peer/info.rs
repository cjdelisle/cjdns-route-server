//! Info about connections to peer supernodes

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::peer::{Peer, PeerList, Peers};

pub struct PeersInfo {
    pub peers: Vec<PeerInfo>,
    pub announcements: usize,
    pub ann_by_hash_len: usize,
}

#[derive(Serialize,Deserialize)]
pub struct PeerInfo {
    pub addr: String,
    pub outstanding_requests: usize,
    pub time_since_msg: Duration,
}

impl Peers {
    pub fn get_info(&self) -> PeersInfo {
        let (hash_count, ann_count) = self.anns.lock().info();
        PeersInfo {
            peers: self.peers.info(),
            announcements: hash_count,
            ann_by_hash_len: ann_count,
        }
    }
}

impl PeerList {
    fn info(&self) -> Vec<PeerInfo> {
        self.list(|peer| peer.info())
    }
}

impl Peer {
    fn info(&self) -> PeerInfo {
        let now = std::time::Instant::now();
        let lmt = *self.last_msg_time.read();
        let since = now - lmt;

        PeerInfo {
            addr: self.addr.clone(),
            outstanding_requests: self.get_outstanding_reqs_count(),
            time_since_msg: since,
        }
    }
}
