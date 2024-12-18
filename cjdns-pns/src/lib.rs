use std::{
    collections::HashMap,
    fmt::Display,
    future::Future,
    sync::Arc,
};
use alloy::primitives::{Address, Bytes, B256, U256};

use eyre::{bail, Result};
use tokio::sync::{broadcast::channel, Mutex};
use itertools::Itertools;

use cjdns_pkt_abi::{Pns as PnsContract,IPNS, PNS_ADDR};
use cjdns_util::now_sec;
use cjdns_eth_rpc::{types::{AlloyTransport, GenericProvider}, EthRpc};

// Aligned with the PNS contract
const PREREG_LIFETIME_SECONDS: u64 = 60*60*24;

const SPECIAL_DOMAINS: &'static [&str] = &[
    "www",
    "status",
    "m",
    "h",
    "docs",
    "explorer",
    "forum",
    "admin",
    "support",
    "api",
    "cdn",
    "staging",
    "dev",
    "blog",
    "ftp",
    "mail",
    "autodiscover",
    "_domainkey",
    "_dmarc",
];

pub struct Domain {
    pub id: u64,
    pub d: IPNS::Domain,
}
impl Domain {
    pub fn name(&self) -> String {
        String::from_utf8_lossy(&self.d.name.to_vec()).to_string()
    }
    pub fn is_subdomain(&self) -> bool {
        self.d.subdomains == 0xff
    }
    pub fn owner_lockup(&self) -> Option<u64> {
        if self.is_subdomain() {
            None
        } else {
            Some(self.d.owner)
        }
    }
}

enum Domains {
    Domains(HashMap<u64,Arc<Domain>>),
    Updating(tokio::sync::broadcast::Receiver<()>),
    Errored,
}

fn pns_contract<P: GenericProvider>(prov: P) -> PnsContract::PnsInstance<AlloyTransport, P> {
    PnsContract::new(PNS_ADDR.parse().unwrap(), prov)
}

struct PnsMut {
    domains: Domains,
}

pub struct Pns {
    m: Mutex<PnsMut>,
    rpc: Arc<EthRpc>,
}
impl Pns {
    pub async fn new(
        rpc: Arc<EthRpc>,
    ) -> Result<Arc<Self>> {
        let out = Arc::new(Self {
            m: Mutex::new(PnsMut{
                domains: Domains::Errored,
            }),
            rpc,
        });

        println!("PNS: Getting domans");
        update_all_domains(&out).await?;

        filter_blacklist(&out).await?;
        filter_create_subdomain(&out).await?;
        filter_destroy(&out).await?;
        filter_destroy_prereg(&out).await?;
        filter_preregister(&out).await?;
        filter_register_domain(&out).await?;
        filter_takeover(&out).await?;
        filter_update_records(&out).await?;
    
        println!("PNS: Done");

        Ok(out)
    }

    async fn handle_err<T,E:Display>(
        self: &Arc<Self>,
        name: &str,
        r: impl Future<Output=Result<T,E>>,
    ) -> Option<T> {
        match r.await {
            Err(e) => {
                println!("Error in {name}: {e}");
                self.m.lock().await.domains = Domains::Errored;
                None
            }
            Ok(r) => Some(r)
        }
    }

    pub async fn with_domains<T>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut HashMap<u64,Arc<Domain>>) -> Result<T>,
    ) -> Result<T> {
        loop {
            let mut m = self.m.lock().await;
            match &mut m.domains {
                Domains::Updating(l) => {
                    let mut c = l.resubscribe();
                    drop(m);
                    let _ = c.recv().await;
                }
                Domains::Domains(u) => {
                    return f(u);
                }
                Domains::Errored => {
                    drop(m);
                    update_all_domains(self).await?;
                }
            }
        }
    }

    pub async fn compute_prehash(self: &Arc<Self>, lockup_id: u64, name: &[u8], records: &[u8]) -> Result<B256> {
        self.rpc.read_eth(|prov|async move {
            let name = Bytes::copy_from_slice(name);
            let records = Bytes::copy_from_slice(records);
            Ok(pns_contract(prov).computePreregHash(lockup_id, name, records).call().await?._0)
        }).await
    }

    pub async fn prereg_exists(self: &Arc<Self>, prereg_hash: B256) -> Result<bool> {
        self.rpc.read_eth(|prov|async move {
            let x = pns_contract(prov).getPrereg(prereg_hash).call().await?;
            Ok::<bool,eyre::ErrReport>(x.timestamp > 0 && now_sec() + 60 < x.timestamp + PREREG_LIFETIME_SECONDS)
        }).await
    }

    pub async fn min_lockup(self: &Arc<Self>) -> Result<U256> {
        self.rpc.read_eth(|prov|async move {
            Ok(pns_contract(prov).currentMinLockup().call().await?.price)
        }).await
    }

    pub async fn domain_available(self: &Arc<Self>, name: &str) -> Result<bool> {
        if SPECIAL_DOMAINS.contains(&name) {
            Ok(false)
        } else {
            self.with_domains(|doms|{
                Ok(doms.values().find(|d|d.name() == name).is_none())
            }).await
        }
    }

    pub async fn user_authorized(self: &Arc<Self>, addr: Address) -> Result<(bool, bool)> {
        self.rpc.read_eth(|prov|async move {
            let pns = pns_contract(prov);
            let is_enforcing = pns.isRegistrationWhitelistActive().call().await?._0;
            let is_authorized = pns.isAddressWhitelisted(addr).call().await?._0;
            Ok((is_authorized, is_enforcing))
        }).await
    }
}

const UNITS_PER_REQ: usize = 16;

async fn get_all_domains(inf: &Arc<Pns>) -> Result<HashMap<u64,Arc<Domain>>> {
    inf.rpc.read_eth(|prov|async move {
        let pns = pns_contract(prov);
        let mut out = HashMap::new();
        let nid: u64 = pns.nextDomainId().call().await?._0.to();
        let chks = (0..nid).chunks(UNITS_PER_REQ).into_iter()
            .map(|c|c.collect::<Vec<_>>())
            .collect::<Vec<_>>();
        for v in chks {
            println!("PNS: get_all_domains([{:?}])", v);
            let x = pns.getDomains(v.clone()).call().await?;
            for (d, id) in x.out.into_iter().zip(v.into_iter()) {
                if d.owner > 0 {
                    out.insert(id, Arc::new(Domain{ id, d }));
                }
            }
        }
        Ok(out)
    }).await
}

async fn update_all_domains(inf: &Arc<Pns>) -> Result<()> {
    let send = {
        let mut m = inf.m.lock().await;
        let (send, recv) = channel(1);
        m.domains = Domains::Updating(recv);
        send
    };
    let r = match get_all_domains(inf).await {
        Ok(res) => {
            let mut m = inf.m.lock().await;
            m.domains = Domains::Domains(res);
            Ok(())
        }
        Err(e) => {
            let mut m = inf.m.lock().await;
            m.domains = Domains::Errored;
            Err(e)
        }
    };
    drop(send);
    r
}

/// Checks if a string slice is a valid DNS label.
/// - Must start with a lowercase letter or digit.
/// - Can contain lowercase letters, digits, or hyphens.
/// - Must end with a lowercase letter or digit.
/// - Length must be between 1 and 63 characters.
/// - All letters must be lowercase.
///
/// # Arguments
///
/// * `label` - A string slice to check for validity as a DNS label
///
/// # Returns
///
/// * `true` if the label is valid, `false` otherwise.
pub fn is_valid_domain_label(label: &str) -> bool {
    // Check length
    if label.len() < 1 || label.len() > 63 {
        return false;
    }

    // Check if it starts and ends with a lowercase letter or digit
    if !label.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) ||
       !label.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }

    // Check if all characters are valid (lowercase letters, digits, or hyphens)
    if !label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return false;
    }

    // Check for consecutive hyphens (not allowed in DNS labels)
    if label.contains("--") {
        return false;
    }

    true
}

// event Register(address sender, uint64 id, uint64 lockupId, bytes name, bytes records);
async fn filter_register_domain(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.Register_filter(),
        |srv, reg, log| async move {
            let u = Arc::new(Domain {
                d: IPNS::Domain {
                    owner: reg.lockupId,
                    name: reg.name,
                    records: reg.records,
                    subdomains: 0,
                    blacklisted: false,
                },
                id: reg.id,
            });
            println!("TX {:?} Register({}({})) BY: {} {}",
                log.transaction_hash,
                u.d.name,
                u.id,
                reg.sender,
                reg.lockupId,
            );
            srv.handle_err(
                "Register/with_domains",
                srv.with_domains(move |units| {
                    units.insert(u.id, u);
                    Ok(())
                })
            ).await;
        }
    ).await
}


// event UpdateRecords(address sender, uint64 id, bytes records);
async fn filter_update_records(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.UpdateRecords_filter(),
        |srv, ur, log| async move {
            println!("TX {:?} UpdateRecords({}) BY: {}",
                log.transaction_hash,
                ur.id,
                ur.sender,
            );
            srv.handle_err(
                "UpdateRecords/with_domains",
                srv.with_domains(move |units| {
                    if let Some(d) = units.get_mut(&ur.id) {
                        let mut dd = Domain{
                            id: d.id,
                            d: d.d.clone(),
                        };
                        dd.d.records = ur.records;
                        *d = Arc::new(dd);
                        Ok(())
                    } else {
                        bail!("Unable to find domain with id {}", ur.id);
                    }
                })
            ).await;
        }
    ).await
}

async fn filter_takeover(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.Takeover_filter(),
        |srv, takeover, log| async move {
            println!("TX {:?} Takeover({}) BY: {} - Old Lockup: {} New Lockup: {}",
                log.transaction_hash,
                takeover.id,
                takeover.sender,
                takeover.oldLockupId,
                takeover.newLockupId,
            );

            srv.handle_err(
                "Takeover/with_domains",
                srv.with_domains(move |units| {
                    if let Some(d) = units.get_mut(&takeover.id) {
                        let mut dd = Domain{
                            id: d.id,
                            d: d.d.clone(),
                        };
                        dd.d.owner = takeover.newLockupId;
                        dd.d.records = takeover.records;
                        *d = Arc::new(dd);
                        Ok(())
                    } else {
                        bail!("Unable to find domain with id {} for takeover", takeover.id);
                    }
                })
            ).await;
        }
    ).await
}

async fn filter_create_subdomain(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.CreateSubdomain_filter(),
        |srv, cs, log| async move {
            println!("TX {:?} CreateSubdomain({}({})) BY: {} Parent: {}",
                log.transaction_hash,
                cs.name,
                cs.id,
                cs.sender,
                cs.parentId,
            );

            srv.handle_err(
                "CreateSubdomain/with_domains",
                srv.with_domains(move |units| {
                    if let Some(parent_domain) = units.get_mut(&cs.parentId) {
                        let new_subdomain = Domain {
                            d: IPNS::Domain {
                                owner: cs.parentId,
                                name: cs.name,
                                records: cs.records,
                                subdomains: 0xff, // ff = we ARE a subdomain
                                blacklisted: parent_domain.d.blacklisted,
                            },
                            id: cs.id,
                        };
                        let mut pd = Domain {
                            d: parent_domain.d.clone(),
                            id: parent_domain.id,
                        };
                        pd.d.subdomains += 1;
                        *parent_domain = Arc::new(pd);
                        units.insert(cs.id, Arc::new(new_subdomain));
                        Ok(())
                    } else {
                        bail!("Unable to find parent domain with id {} for creating subdomain", cs.parentId);
                    }
                })
            ).await;
        }
    ).await
}

async fn filter_destroy(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.Destroy_filter(),
        |srv, destroy, log| async move {
            println!("TX {:?} Destroy({}) BY: {}",
                log.transaction_hash,
                destroy.id,
                destroy.sender,
            );

            srv.handle_err(
                "Destroy/with_domains",
                srv.with_domains(move |units| {
                    if let Some(domain) = units.remove(&destroy.id) {
                        if domain.d.subdomains == 0xff {
                            // This is a subdomain, so we need to decrement the subdomains count of its parent
                            if let Some(parent_domain) = units.get_mut(&domain.d.owner) {
                                let mut parentd = Domain{
                                    d: parent_domain.d.clone(),
                                    id: parent_domain.id,
                                };
                                parentd.d.subdomains -= 1;
                                *parent_domain = Arc::new(parentd);
                            } else {
                                bail!("Unable to find parent domain with id {} to decrement subdomain count", domain.d.owner);
                            }
                        }
                        Ok(())
                    } else {
                        bail!("Unable to find domain with id {} for destruction", destroy.id);
                    }
                })
            ).await;
        }
    ).await
}

async fn filter_blacklist(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.Blacklist_filter(),
        |srv, blacklist, log| async move {
            println!("TX {:?} Blacklist({}) BY: {} - Blacklisted: {}",
                log.transaction_hash,
                blacklist.id,
                blacklist.sender,
                if blacklist.isBlacklisted { "Yes" } else { "No" },
            );

            srv.handle_err(
                "Blacklist/with_domains",
                srv.with_domains(move |units| {
                    if let Some(domain) = units.get_mut(&blacklist.id) {
                        let mut dd = Domain{
                            id: domain.id,
                            d: domain.d.clone(),
                        };
                        dd.d.blacklisted = blacklist.isBlacklisted;
                        *domain = Arc::new(dd);
                        Ok(())
                    } else {
                        bail!("Unable to find domain with id {} for blacklisting", blacklist.id);
                    }
                })
            ).await;
        }
    ).await
}

async fn filter_preregister(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.Preregister_filter(),
        |_, prereg, log| async move {
            println!("TX {:?} Preregister - NameHash: {:?}, BY: {}, LockupId: {}",
                log.transaction_hash,
                prereg.nameHash,
                prereg.sender,
                prereg.lockupId,
            );
            Ok::<(),eyre::ErrReport>(())
        }
    ).await
}

async fn filter_destroy_prereg(srv: &Arc<Pns>) -> Result<()> {
    srv.rpc.subscribe(
        Arc::clone(srv),
        PNS_ADDR.parse()?,
        PnsContract::new,
        |pns| pns.DestroyPrereg_filter(),
        |_, destroy_prereg, log| async move {
            println!("TX {:?} DestroyPrereg - NameHash: {:?}, BY: {}, LockupId: {}",
                log.transaction_hash,
                destroy_prereg.nameHash,
                destroy_prereg.sender,
                destroy_prereg.lockupId,
            );
            Ok::<(),eyre::ErrReport>(())
        }
    ).await
}