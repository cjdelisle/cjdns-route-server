use std::{net::SocketAddr, sync::Arc};

use cjdns_bencode::object::{Dict,Get};
use eyre::{bail, Result};
use cjdns_admin::{Connection, Opts};
use cjdns_bytes::dnsseed::PeeringLine;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::CjdnsAdminConfig;

fn parse_address(address: &str) -> Result<(&str, &str)> {
    if !address.starts_with('v') {
        bail!("Address {address} must begin with 'v'");
    }
    let Some(dot0) = address.find('.') else {
        bail!("Address {address} missing '.'");
    };
    if address.as_bytes().get(dot0 + 20) != Some(&b'.') {
        // .0000.0000.0000.0001.
        bail!("Address {address} find('.')+20 != '.'");
    }
    let path = &address[dot0+1..dot0+20];
    if address.len() < 25 {
        bail!("Address {address} too short");
    }
    let key = &address[dot0+21..];
    Ok((path, key))
}

#[derive(Clone)]
pub struct Cjdns {
    conn: Arc<Mutex<Connection>>,
}
impl Cjdns {
    pub async fn new(cac: &CjdnsAdminConfig) -> Result<Self> {
        let cjdns = cjdns_admin::connect(Some(Opts{
            addr: Some(cac.host.clone()),
            port: Some(cac.port),
            password: Some(cac.pass.clone()),
            config_file_path: None,
            anon: false,
        })).await?;
        Ok(Self{ conn: Arc::new(Mutex::new(cjdns)) })
    }
    pub async fn get_best_iface(&self, sa: &SocketAddr) -> Result<i64> {
        let ifaces = get_interfaces(self).await?;
        for iface in ifaces {
            if sa.is_ipv6() && iface.name.starts_with("UDP/IPv6/") {
                return Ok(iface.if_num);
            } else if sa.is_ipv4() && iface.name.starts_with("UDP/IPv4/") {
                return Ok(iface.if_num);
            }
        }
        bail!("No usable interface found");
    }

    pub async fn get_snode(&self, address: &str) -> Result<Option<String>> {
        // SwitchPinger_ping --path=0000.0000.0000.0013 --snode=1

        let (path, _) = parse_address(address)?;
        log::debug!("SwitchPinger_ping({path}, snode=1)");
        let mut args = Dict::new();
        args.insert("path", path.to_string());
        args.insert("snode", 1);
        let reply =
            self.conn.lock().await.invoke("SwitchPinger_ping", args).await?;
        if reply.get_str("result")? != "pong" {
            bail!("Got result: {}", reply.get_str("result")?);
        }
        Ok(reply.try_get("snode")?)
    }

    pub async fn begin_conn(&self, iface_num: i64, worker: usize, peer: &PeeringLine) -> Result<()> {
        // cjdnstool cexec UDPInterface_beginConnection --address=<String> --publicKey=<String>
        //     [--interfaceNumber=<Int>] [--login=<String>] [--password=<String>]
        //     [--peerName=<String>] [--version=<Int>]
        // Remote error will cause invoke() to fail.
        log::debug!("UDPInterface_beginConnection({})", &peer.address);
        let mut args = Dict::new();
        args.insert("address", peer.address.clone());
        args.insert("publicKey", peer.public_key.clone());
        args.insert("interfaceNumber", iface_num);
        args.insert("login", peer.login.clone());
        args.insert("password", peer.password.clone());
        args.insert("peerName", format!("TESTING/{}/{}", worker, peer.address));
        args.insert("version", peer.version as i64);
        self.conn.lock().await.invoke("UDPInterface_beginConnection", args).await?;
        Ok(())
    }

    pub async fn remove_conns(&self, worker: Option<usize>) -> Result<()> {
        let ps = self.peer_stats().await?;
        let template = if let Some(worker) = worker {
            format!("TESTING/{}/", worker)
        } else {
            "TESTING/".to_string()
        };
        for p in &ps {
            let Some(user) = &p.user else {
                continue;
            };
            if !user.starts_with(&template) {
                continue;
            }
            let (_, key) = parse_address(&p.addr)?;
            log::debug!("InterfaceController_disconnectPeer({})", key);
            let mut args = Dict::new();
            args.insert("pubkey", key.to_string());
            self.conn.lock().await.invoke("InterfaceController_disconnectPeer", args).await?;
        }
        Ok(())
    }

    pub async fn peer_stats_of(&self, public_key: &str) -> Result<Option<PeerStats>> {
        let peers = self.peer_stats().await?;
        for p in peers {
            if p.addr.contains(public_key) {
                return Ok(Some(p));
            }
        }
        Ok(None)
    }

    pub async fn peer_stats(&self) -> Result<Vec<PeerStats>> {
        #[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
        struct Ps {
            pub peers: Vec<PeerStats>,
            pub more: Option<u64>,
            pub total: i64,
        }
        let mut out = Vec::new();
        let mut page = 0;
        loop {
            let mut args = Dict::new();
            args.insert("page", page);
            let ret = self.conn.lock().await.invoke(
                "InterfaceController_peerStats",
                args
            ).await?;
            let peers = ret.get_list("peers")?;
            for p in peers.iter() {
                out.push(PeerStats::try_from(p.as_dict()?)?);
            }
            if ret.has("more") {
                page += 1;
                continue;
            } else {
                return Ok(out);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerStats {
    #[serde(rename = "addr")]
    pub addr: String,
    
    #[serde(rename = "bytesIn")]
    pub bytes_in: i64,
    
    #[serde(rename = "bytesOut")]
    pub bytes_out: i64,
    
    #[serde(rename = "duplicates")]
    pub duplicates: u32,
    
    #[serde(rename = "ifNum")]
    pub if_num: u32,
    
    #[serde(rename = "isIncoming")]
    pub is_incoming: u8,
    
    #[serde(rename = "last")]
    pub last: i64,
    
    #[serde(rename = "lladdr")]
    pub lladdr: String,

    #[serde(rename = "lostPackets")]
    pub lost_packets: u32,
    
    #[serde(rename = "noiseProto")]
    pub noise_proto: u32,
    
    #[serde(rename = "receivedOutOfRange")]
    pub received_out_of_range: u32,
    
    #[serde(rename = "receivedPackets")]
    pub received_packets: i64,
    
    #[serde(rename = "recvKbps")]
    pub recv_kbps: u32,
    
    #[serde(rename = "sendKbps")]
    pub send_kbps: u32,
    
    #[serde(rename = "state")]
    pub state: String,

    pub user: Option<String>,
}
impl TryFrom<&Dict<'_>> for PeerStats {
    type Error = eyre::Error;
    fn try_from(d: &Dict<'_>) -> Result<Self> {
        Ok(Self{
            addr: d.get("addr")?,
            bytes_in: d.get("bytesIn")?,
            bytes_out: d.get("bytesOut")?,
            duplicates: d.get("duplicates")?,
            if_num: d.get("ifNum")?,
            is_incoming: d.get("isIncoming")?,
            last: d.get("last")?,
            lladdr: d.get("lladdr")?,
            lost_packets: d.get("lostPackets")?,
            noise_proto: d.get("noiseProto")?,
            received_out_of_range: d.get("receivedOutOfRange")?,
            received_packets: d.get("receivedPackets")?,
            recv_kbps: d.get("recvKbps")?,
            send_kbps: d.get("sendKbps")?,
            state: d.get("state")?,
            user: d.try_get("user")?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq)]
pub struct SwitchPingReply {
    pub ms: u32,
    pub path: String,
    pub result: String,
    pub version: Option<u32>,
    pub data: Option<String>,
    pub snode: Option<String>,
}
impl TryFrom<&Dict<'_>> for SwitchPingReply {
    type Error = eyre::Error;
    fn try_from(d: &Dict<'_>) -> Result<Self> {
        Ok(Self{
            ms: d.get("ms")?,
            path: d.get("path")?,
            result: d.get("result")?,
            version: d.try_get("version")?, 
            data: d.try_get("data")?,
            snode: d.try_get("snode")?,
        })
    }
}

#[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
struct Interface {
    #[serde(rename = "beaconState")]
    pub beacon_state: String,
    #[serde(rename = "ifNum")]
    pub if_num: i64,
    pub name: String,
}
impl TryFrom<&Dict<'_>> for Interface {
    type Error = eyre::Error;
    fn try_from(d: &Dict<'_>) -> Result<Self> {
        Ok(Self{
            beacon_state: d.get("beaconState")?,
            if_num: d.get("ifNum")?,
            name: d.get("name")?,
        })
    }
}

async fn get_interfaces(cjdns: &Cjdns) -> Result<Vec<Interface>> {
    let mut out = Vec::new();
    let mut page = 0;
    loop {
        let mut args = Dict::new();
        args.insert("page", page);
        let ret =
            cjdns.conn.lock().await.invoke("InterfaceController_interfaces", args).await?;
        for iface in ret.get_list("ifaces")?.iter() {
            out.push(Interface::try_from(iface.as_dict()?)?);
        }
        if ret.has("more") {
            page += 1;
            continue;
        } else {
            return Ok(out);
        }
    }
}