use std::{
    any::Any,
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};

use alloy::primitives::Address;
use anyhow::{bail, Result};

use crate::types::GenericProvider;

pub struct RpcInfo {
    pub http: String,
    is_dead: AtomicBool,
}
impl RpcInfo {
    pub fn new(http: String, is_dead: bool) -> Self {
        Self {
            http,
            is_dead: AtomicBool::new(is_dead),
        }
    }
    pub fn is_dead(&self) -> bool {
        let dead = self.is_dead.load(std::sync::atomic::Ordering::Relaxed);
        if dead {
            // println!("RPC {} is dead", self.name);
        }
        dead
    }
    pub async fn set_alive(&self) {
        self.is_dead.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    pub async fn set_dead(&self, reason: &str) {
        let current = self.is_dead();
        if !current {
            println!("MARKING {} AS DEAD BECAUSE {}", self.http, reason);
            self.is_dead.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct RpcInstanceMut {
    contracts: HashMap<Address, Box<dyn Any + Send + Sync>>,
}

pub struct RpcInstance<P: GenericProvider> {
    m: Option<RpcInstanceMut>,
    pub provider: P,
    pub name: String,
}
impl<P: GenericProvider> RpcInstance<P> {
    pub fn new(info: &Arc<RpcInfo>, provider: P) -> Result<Self> {
        Ok(Self {
            m: Some(Default::default()),
            provider,
            name: info.http.chars().take(25).collect(),
        })
    }
    pub fn contract<T>(
        &mut self,
        address: Address,
        f: fn(a: Address, p: P) -> T,
    ) -> Result<&T>
        where T: 'static + Send + Sync
    {
        if self.m.as_ref().unwrap().contracts.get(&address).is_none() {
            let mut m = self.m.take().unwrap();
            m.contracts.insert(address.clone(), Box::new(f(address.clone(), self.provider.clone())));
            self.m = Some(m);
        }
        if let Some(contract) = self.m.as_ref().unwrap().contracts.get(&address) {
            match contract.downcast_ref::<T>() {
                Some(t) => Ok(t),
                None => {
                    bail!("Downcast failed");
                }
            }
        } else {
            bail!("No such token");
        }
    }
}
