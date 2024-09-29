use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::io::Read;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use byteorder::{ReadBytesExt,WriteBytesExt,BE};
use serde::{Deserialize, Serialize};

use crate::message::{Message, RWrite};
use crate::var_int::{read_var_int, write_var_int};
use crate::readext::ReadExt;

pub struct AuthorizedPassword {
    pub password: String,
    pub user: String,
}

#[derive(Serialize,Deserialize)]
pub struct PeeringLine {
    pub address: String,
    pub public_key: String,
    pub login: String,
    pub password: String,
    pub version: u32,
}

#[derive(Default,Debug,PartialEq,Clone)]
pub struct PeerID {
    pub id: Vec<u8>,
}
impl PeerID {
    pub fn encode(&self, w: &mut impl RWrite) -> Result<()> {
        if self.id.len() > 64 {
            bail!("Invalid PeerID, max length 64");
        }
        let len0 = w.len();
        w.write_all(&self.id)?;
        let len = w.len() - len0 + 2;
        w.write_u8(len as _)?;
        w.write_u8(PEER_ID)?;
        Ok(())
    }
    pub fn decode(r: &mut impl Read) -> Result<Self> {
        let mut id = Vec::new();
        r.read_to_end(&mut id)?;
        Ok(Self{id})
    }
}

#[derive(Debug,PartialEq,Clone)]
pub struct CjdnsPeer {
    pub address: SocketAddr,
    pub pubkey: [u8;32],
    pub login: u16,
    pub password: [u8;8],
    pub version: u32,
}
impl CjdnsPeer {
    pub fn peering_line(&self) -> PeeringLine {
        PeeringLine{
            address: self.address.to_string(),
            public_key: cjdns_keys::CJDNSPublicKey::from(self.pubkey.clone()).to_string(),
            login: self.mk_login(),
            password: self.mk_pass(),
            version: self.version,
        }
    }

    pub fn authorized_password(&self) -> AuthorizedPassword {
        AuthorizedPassword{
            password: self.mk_pass(),
            user: self.mk_login(),
        }
    }

    fn mk_pass(&self) -> String {
        format!("AP_PASS: {}", STANDARD_NO_PAD.encode(self.password))
    }

    fn mk_login(&self) -> String {
        format!("AP_LOGIN: {}", self.login)
    }
    
    // [address:4|16][port:2][login:1-9][passwd:8][pubkey:32][version:1-9]
    pub fn encode(&self, w: &mut impl RWrite) -> Result<()> {
        let len0 = w.len();
        write_var_int(self.version, w)?;
        w.write_all(&self.pubkey)?;
        w.write_all(&self.password)?;
        write_var_int(self.login, w)?;
        w.write_u16::<BE>(self.address.port())?;
        let code = match self.address {
            SocketAddr::V4(v4) => {
                w.write_all(&v4.ip().octets())?;
                UDP4_PEER
            }
            SocketAddr::V6(v6) => {
                w.write_all(&v6.ip().octets())?;
                UDP6_PEER
            }
        };
        let len = w.len() - len0 + 2;
        w.write_u8(len as _)?;
        w.write_u8(code)?;
        Ok(())
    }
    
    pub fn decode(code: u8, r: &mut impl Read) -> Result<Self> {
        let mut sa = match code {
            UDP4_PEER => {
                let mut x = [0_u8;4];
                r.read_exact(&mut x)?;
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(x), 0))
            }
            UDP6_PEER => {
                let mut x = [0_u8;16];
                r.read_exact(&mut x)?;
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(x), 0, 0, 0))
            }
            _ => {
                bail!("Unexpected code: {code}");
            }
        };
        sa.set_port(r.read_u16::<BE>()?);
        Ok(Self{
            address: sa,
            login: read_var_int(r)?,
            password: r.read_bytes()?,
            pubkey: r.read_bytes()?,
            version: read_var_int(r)?,
        })
    }
}

pub const SNODE: u8 = 0x01;
pub const UDP4_PEER: u8 = 0x02;
pub const UDP6_PEER: u8 = 0x03;
pub const PEER_ID: u8 = 0x04;

#[derive(Default,Debug,PartialEq)]
pub struct CjdnsTxtRecord {
    pub peers: Vec<CjdnsPeer>,
    pub snode_pubkey: Option<[u8;32]>,
    pub peer_id: Option<PeerID>,
    pub unknown_records: Vec<(u8,Vec<u8>)>
}
impl CjdnsTxtRecord {
    fn parse_snode(&mut self, data: &mut impl Read) -> Result<()> {
        let mut snode = [0_u8;32];
        data.read_exact(&mut snode)?;
        self.snode_pubkey = Some(snode);
        Ok(())
    }
    fn write_snode(&self, data: &mut impl RWrite) -> Result<()> {
        if let Some(snode) = &self.snode_pubkey {
            data.write_all(snode)?;
            data.write_all(&[SNODE,(snode.len() + 2) as u8])?;
        }
        Ok(())
    }
    fn parse_peerid(&mut self, data: &mut impl Read) -> Result<()> {
        self.peer_id = Some(PeerID::decode(data)?);
        Ok(())
    }
    fn write_peerid(&self, data: &mut impl RWrite) -> Result<()> {
        if let Some(pid) = &self.peer_id {
            pid.encode(data)?
        }
        Ok(())
    }
    fn from_tlv(&mut self, t: u8, mut data: &[u8]) -> Result<()> {
        match t {
            PEER_ID => self.parse_peerid(&mut data)?,
            SNODE => self.parse_snode(&mut data)?,
            UDP4_PEER | UDP6_PEER => {
                self.peers.push(CjdnsPeer::decode(t, &mut data)?);
            }
            _ => self.unknown_records.push((t, Vec::from(data))),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<String> {
        let mut data = Message::with_chunk_size(512);
        self.encode_bin(&mut data)?;
        Ok(String::new() + "cjdns0=" + &STANDARD_NO_PAD.encode(data.as_vec()))
    }

    pub fn encode_bin(&self, data: &mut impl RWrite) -> Result<()> {
        for p in self.peers.iter().rev() {
            p.encode(data)?;
        }
        self.write_snode(data)?;
        self.write_peerid(data)?;
        Ok(())
    }

    pub fn decode_bin(bytes: &[u8]) -> Result<Self> {
        let mut out = Self::default();
        for (t, elem) in parse_tlv(bytes)? {
            out.from_tlv(t, elem)?;
        }
        Ok(out)
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = if let Some(s) = s.strip_prefix("cjdns0=") {
            s
        } else {
            bail!("Missing cjdns0= prefix");
        };
        let bytes =
            STANDARD_NO_PAD.decode(s).context("Could not decode base64")?;
        Self::decode_bin(&bytes)
    }
}

fn parse_tlv(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut cursor = 0;
    let mut out = Vec::new();
    // println!("Begin parse TLV");
    while cursor + 1 < bytes.len() {
        let t = bytes[cursor];
        let l = bytes[cursor + 1] as usize;
        // println!("TLV({t},{l}) cursor={cursor} len() = {}", bytes.len());
        if l < 2 {
            bail!("Invalid item length: {l}");
        } else if l + cursor > bytes.len() {
            bail!("TLV is truncated");
        }
        out.push((t, &bytes[cursor + 2 .. cursor + l]));
        cursor += l;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use rand::{rngs::ThreadRng, Rng};
    use crate::dnsseed::{CjdnsPeer, CjdnsTxtRecord};

    use super::PeerID;

    fn random_peer(rng: &mut ThreadRng) -> CjdnsPeer {
        let address = if true {
            SocketAddr::new(
                Ipv6Addr::from_bits(rng.gen()).into(),
                rng.gen(),
            )
        } else {
            SocketAddr::new(
                Ipv4Addr::from_bits(rng.gen()).into(),
                rng.gen(),
            )
        };
        CjdnsPeer{
            address,
            pubkey: rng.gen(),
            login: rng.gen(),
            password: rng.gen(),
            version: rng.gen(),
        }
    }

    fn random_rec() -> CjdnsTxtRecord {
        let mut rng = rand::thread_rng();
        CjdnsTxtRecord {
            peers: (0..3).map(|_|random_peer(&mut rng)).collect(),
            snode_pubkey: rng.gen(),
            unknown_records: Vec::new(),
            peer_id: if rng.gen() {
                Some(PeerID{ id: rng.gen::<[u8;32]>().into() })
            } else {
                None
            }
        }
    }

    #[test]
    fn test() {
        for _ in 0..1000 {
            let rr = random_rec();
            // println!(">> {rr:?}");
            let s0 = rr.encode().unwrap();
            // println!(">> {s0}");
            assert!(s0.len() < 500);
            let rr1 = CjdnsTxtRecord::decode(&s0).unwrap();
            let s1 = rr1.encode().unwrap();
            assert_eq!(s0,s1);
            assert_eq!(rr,rr1);
        }
    }

    #[test]
    fn test_demo() {
        let rr = random_rec();
        println!("TXT record: {}", rr.encode().unwrap());
        for (_, p) in rr.peers.iter().enumerate() {
            let pl = p.peering_line();
            println!(r#"  "{}":{{"login":"{}","password":"{}","publicKey":"{}"}},"#,
                pl.address,
                pl.login,
                pl.password,
                pl.public_key,
            );
        }
    }
}