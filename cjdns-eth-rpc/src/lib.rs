use std::{
    collections::{HashMap, VecDeque},
    future::{Future, IntoFuture},
    sync::Arc,
    time::Duration,
};

use alloy::{
    contract::EventSubscription, primitives::{Address, B256}, providers::{ProviderBuilder, WsConnect}, rpc::types::Log, sol_types::SolEvent, transports::http::reqwest::Url
};
use eyre::{eyre, bail, Result};
use futures_util::StreamExt;
use rpcinstance::{RpcInfo, RpcInstance};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex, RwLock};
use rand::Rng;

pub mod types;
pub mod error;
pub mod rpcinstance;

use types::{AlloyEvent, AlloyFilledProvider, AlloyProviderWs, GenericProvider, RPC_MAX_TRIES};

trait MkProvider<X: GenericProvider>: Fn(Url) -> X {}
impl<P:GenericProvider,X> MkProvider<P> for X where X: Fn(Url) -> P {}

async fn notify_check(nf: &Arc<EthRpc>, txid: B256, ws_url: &Arc<String>) -> bool {
    let mut dq = nf.txns.write().await;
    let now = cjdns_util::now_sec();
    while let Some(f) = dq.front() {
        if f.0 > now - 600 {
            break;
        }
        dq.pop_front();
    }
    for (_, ent, url) in dq.iter() {
        if ent == &txid {
            return url == ws_url;
        }
    }
    dq.push_back((now, txid, Arc::clone(ws_url)));
    drop(dq);
    nf.notify.lock().await.send(txid).expect("Receiver was dropped, should not happen");
    true
}

async fn create_provider(websocket: &str) -> Result<AlloyProviderWs> {
    println!("Connecting WebSocket {websocket}");
    let ws = WsConnect::new(websocket);
    Ok(ProviderBuilder::new().on_ws(ws).await?)
}

fn mk_provider(url: Url) -> AlloyFilledProvider {
    ProviderBuilder::new()
        .with_recommended_fillers()
        //.wallet(wallet.clone())
        .on_http(url)
}

#[derive(Clone,Serialize,Deserialize)]
pub struct EthRpcConfig {
    pub chance_dead_rpc: f64,
    pub ws_rpcs: Vec<String>,
    pub http_rpcs: Vec<String>,
}
pub struct EthRpc {
    ws: HashMap<Arc<String>,Mutex<(AlloyProviderWs,usize)>>,
    txns: RwLock<VecDeque<(u64, B256, Arc<String>)>>,
    update: broadcast::Receiver<B256>,
    notify: Mutex<broadcast::Sender<B256>>,
    chance_dead_rpc: f64,
    rpcs: Vec<Arc<RpcInfo>>,
}
impl EthRpc {
    pub async fn new(config: &EthRpcConfig) -> Result<Arc<Self>> {
        let mut ws = HashMap::new();
        for url in &config.ws_rpcs {
            let p = create_provider(&url).await?;
            ws.insert(Arc::new(url.to_string()), Mutex::new((p,0)));
        }
        let mut rpcs = Vec::new();
        for url in &config.http_rpcs {
            rpcs.push(Arc::new(RpcInfo::new(url.clone(), false)));
        }
        let (s, update) = broadcast::channel(16);
        Ok(Arc::new(Self{
            ws,
            txns: Default::default(),
            update,
            notify: Mutex::new(s),
            chance_dead_rpc: config.chance_dead_rpc,
            rpcs,
        }))
    }
    pub async fn wait_txn(self: &Arc<Self>, txid: B256) -> Result<()> {
        tokio::select! {
            res = self.wait0(txid) => {
                res
            }
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                bail!("Timeout");
            }
        }
    }
    pub async fn subscribe<X,C,O,FM,FE,R>(
        self: &Arc<Self>,
        ctx: C,
        address: Address,
        mk_contract: FM,
        mk_filter: fn(&O) -> AlloyEvent<X>,
        on_event: FE,
    ) -> Result<()>
        where
            X: 'static + Send + Sync + SolEvent,
            C: 'static + Clone + Send + Sync,
            O: 'static + Send + Sync,
            FM: 'static + Send  + Sync + Fn(Address, AlloyProviderWs) -> O,
            FE: 'static + Clone + Send + Sync + Fn(C, X, Log) -> R,
            R: 'static + Send + Future,
    {
        let subs = Arc::new(Subscribe{
            nf: Arc::clone(self),
            ctx: ctx.clone(),
            address,
            mk_contract,
            mk_filter,
            on_event,
        });
        for (ws, _) in &self.ws {
            tokio::task::spawn(Arc::clone(&subs).thread(Arc::clone(ws)));
        }
        Ok(())
    }
    pub async fn read_eth<Y,FY,F>(
        &self,
        f: F,
    ) -> Result<Y>
        where
            F: Fn(AlloyFilledProvider) -> FY,
            FY: IntoFuture<Output=eyre::Result<Y>>,
    {
        let mut i = 0;
        loop {
            i += 1;
            let (rpc, rpc_info) = self.rpc(mk_provider).await?;
            let _provider = rpc.provider.clone();
            tokio::select! {
                res = f(rpc.provider).into_future() => {
                    match res {
                        Err(e) => {
                            error::handle_generic_error(e.into(), i, &rpc_info).await?;
                        }
                        Ok(res) => {
                            rpc_info.set_alive().await;
                            return Ok(res);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    if i > RPC_MAX_TRIES {
                        return Err(eyre!("Failed after {RPC_MAX_TRIES} tries to read transaction"));
                    } else {
                        println!("read_eth() timed out attempt {i}/{RPC_MAX_TRIES}, retry...");
                    }
                }
            }
        }
    }


    async fn rpc<P:GenericProvider>(&self, mk_provider: impl MkProvider<P>) -> Result<(RpcInstance<P>,Arc<RpcInfo>)> {
        let choice = rand::thread_rng().gen_range(0.0,1.0);
        let try_dead = choice < self.chance_dead_rpc;
        if let (Some(rpc), _total) = self.rpc_of_type(try_dead, &mk_provider).await? {
            // println!("USING {} RPC: {} OF {}",
            //     if try_dead { "DEAD" } else { "LIVE" },
            //     rpc.name,
            //     total,
            // );
            Ok(rpc)
        } else {
            let try_dead = !try_dead;
            if let (Some(rpc), _total) = self.rpc_of_type(try_dead, &mk_provider).await? {
                // println!("USING {} RPC: {} (all {} RPC are {})",
                //     if try_dead { "DEAD" } else { "LIVE" },
                //     rpc.0.name,
                //     total,
                //     if try_dead { "DEAD" } else { "LIVE" },
                // );
                Ok(rpc)
            } else {
                bail!("No RPCs available");
            }
        }
    }
    async fn rpc_of_type<P:GenericProvider>(
        &self,
        try_dead: bool,
        mk_provider: &impl MkProvider<P>,
    ) -> Result<(Option<(RpcInstance<P>,Arc<RpcInfo>)>,usize)> {
        let count = self.rpcs.iter().filter(|rpc|rpc.is_dead() == try_dead).count();
        if count < 1 {
            return Ok((None, self.rpcs.len()));
        }
        let choice = rand::thread_rng().gen_range(0,count);
        let (_, out) = self.rpcs.iter()
            .filter(|rpc|rpc.is_dead() == try_dead)
            .enumerate()
            .filter(|(i,_)|*i == choice)
            .next()
            .unwrap();
        let url: Url = out.http.parse()?;
        let provider: P = mk_provider(url);
        Ok((
            Some((
                RpcInstance::new(
                    &out,
                    provider,
                )?,
                Arc::clone(&out),
            )),
            self.rpcs.len(),
        ))
    }
    async fn wait0(self: &Arc<Self>, txid: B256) -> Result<()> {
        if self.txns.read().await.iter().find(|(_,s,_)|s == &txid).is_some() {
            return Ok(());
        }
        let mut r = self.update.resubscribe();
        loop {
            let x = r.recv().await?;
            if &x[..] == txid {
                return Ok(());
            }
        }
    }
    async fn get_provider(&self, url: &Arc<String>, min_num: usize) -> Result<(AlloyProviderWs, usize)> {
        let mut m = self.ws.get(url).unwrap().lock().await;
        let (p, num) = &*m;
        if *num >= min_num {
            Ok((p.clone(), *num))
        } else {
            match create_provider(url).await {
                Ok(p) => {
                    *m = (p.clone(),min_num);
                    Ok((p,min_num))
                }
                Err(e) => {
                    println!("Error creating websocket provider for {url}: {e} - sleep 3 seconds");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    Err(e)
                }
            }
        }
    }
}

struct Subscribe<X,C,O,FM,FE,R>
    where
        X: 'static + Send + SolEvent,
        C: 'static + Clone + Send,
        O: 'static + Send,
        FM: 'static + Send + Fn(Address, AlloyProviderWs) -> O,
        FE: 'static + Clone + Send + Fn(C, X, Log) -> R,
        R: 'static + Send + Future,
{
    nf: Arc<EthRpc>,
    ctx: C,
    address: Address,
    mk_contract: FM,
    mk_filter: fn(&O) -> AlloyEvent<X>,
    on_event: FE,
}
impl<X,C,O,FM,FE,R> Subscribe<X,C,O,FM,FE,R>
    where
        X: 'static + Send + SolEvent,
        C: 'static + Clone + Send,
        O: 'static + Send,
        FM: 'static + Send + Fn(Address, AlloyProviderWs) -> O,
        FE: 'static + Clone + Send + Fn(C, X, Log) -> R,
        R: 'static + Send + Future,
{
    async fn handle_events(&self, sub: EventSubscription<X>, url: &Arc<String>) {
        let mut s = sub.into_stream();
        loop {
            let n = s.next().await;
            let (x, log) = match n {
                None => {
                    println!("Got None from WS sync stream {}", url);
                    return;
                }
                Some(Err(e)) => {
                    println!("Got error from WS sync stream {}: {}", url, e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Some(Ok(t)) => t,
            };
            let Some(txid) = log.transaction_hash else {
                // should never happen
                println!("Got tx with no txid from {}", url);
                continue;
            };
            if !notify_check(&self.nf, txid, url).await {
                // We already heard about this txn from another WS
                // println!("WS Log skip {:?} from {ws_url}", log.transaction_hash);
                continue;
            }
            // println!("WS Log event {:?} from {ws_url}", log.transaction_hash);
            (self.on_event)(self.ctx.clone(), x, log).await;
        }
    }    
    async fn thread(self: Arc<Self>, url: Arc<String>) {
        let mut min_num = 0;
        loop {
            let Ok((provider, mn)) = self.nf.get_provider(&url, min_num).await else {
                continue;
            };
            let contract = (self.mk_contract)(self.address, provider);
            let event = (self.mk_filter)(&contract);
            let sub = match event.subscribe().await {
                Ok(sub) => sub,
                Err(e) => {
                    println!("Warn: Unable to subscribe event for {}: {}", url, e);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
            };
            self.handle_events(sub, &url).await;
            println!("Reconnecting WebSocket {url}");
            min_num = mn + 1;
        }
    }
}