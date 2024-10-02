mod config;
mod cjdns;

use std::collections::VecDeque;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use std::io::Write;

use anyhow::{bail, Result};
use cjdns_keys::{PublicKey, CJDNS_IP6};
use cjdns_snode_wire::{SeederListPeer, SeederTestRes, SeederTestResNode};
use cjdns_util::now_sec;
use cjdns_util_http::{json_reply, HttpReply};
use reqwest::Error;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use warp::Filter;

use crate::config::{Config,SnodeConfig};
use crate::cjdns::Cjdns;

async fn load_config(filename: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let contents = tokio::fs::read_to_string(filename).await?;
    let config: Config = serde_yaml::from_str(&contents)?;
    Ok(config)
}

async fn fetch_snode_data(config: &SnodeConfig) -> Result<Vec<SeederListPeer>, Error> {
    let url = format!(
        "http://[{}]:{}/seeder-peers?passwd={}",
        config.host, config.port, config.pass
    );
    let response = reqwest::get(&url).await?;
    let body: Vec<SeederListPeer> = response.json().await?;
    Ok(body)
}

async fn post_snode_testres(config: &SnodeConfig, testres: &SeederTestRes) -> Result<(), Error> {
    let url = format!(
        "http://[{}]:{}/seeder-testres",
        config.host, config.port
    );

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(testres)
        .send()
        .await?;

    response.error_for_status()?; // Ensure the server returned a success status
    Ok(())
}

#[derive(PartialEq,Debug)]
enum Status {
    Ok,
    ConnectTimeout,
    SnodeError(String),
    NoSnode,
    WrongSnode,
    Other(String),
}

struct TestAgent {
    server: Arc<Server>,
    id: usize,
}
impl TestAgent {
    async fn test(&mut self, peer: &SeederListPeer) -> Result<Status> {
        let id = self.id;
        let sa: SocketAddr = peer.peer.address.parse()?;
        log::debug!("[{id}] [{sa}] Delete connections");
        self.server.cjdns.remove_conns(Some(id)).await?;
        log::debug!("[{id}] [{sa}] Getting best iface");
        let iface = self.server.cjdns.get_best_iface(&sa).await?;
        log::debug!("[{id}] [{sa}] Getting peers");
        if self.server.cjdns.peer_stats_of(&peer.peer.public_key).await?.is_some() {
            bail!("Can't test peer {} because we are already connected", peer.peer.address);
        }
        log::debug!("[{id}] [{sa}] Starting connection");
        self.server.cjdns.begin_conn(iface, id, &peer.peer).await?;
        let mut i = 0;
        let mut first_seen = false;
        let pso = loop {
            i += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
            let pso = self.server.cjdns.peer_stats_of(&peer.peer.public_key).await?;
            let Some(pso) = pso else {
                if i < 30 {
                    continue;
                }
                bail!("Peer {} did not register in peer stats within 30 seconds", peer.peer.address);
            };
            if !first_seen {
                log::debug!("[{id}] [{sa}] Connection seen in stats");
                first_seen = true;
            }
            if pso.state == "ESTABLISHED" {
                log::debug!("[{id}] [{sa}] Connection ESTABLISHED");
                break pso;
            }
            if i > 60 {
                log::debug!("[{id}] [{sa}] Connection TIMEOUT");
                return Ok(Status::ConnectTimeout);
                // bail!("Peer {} did not become ESTABLISHED within 60 seconds", peer.peer.address);
            }
        };
        i = 0;
        let snode = loop {
            i += 1;
            log::debug!("[{id}] [{sa}] Get snode attempt [{i}]");
            match self.server.cjdns.get_snode(&pso.addr).await {
                Ok(res) => break res,
                Err(e) => {
                    if i >= 5 {
                        log::debug!("[{id}] [{sa}] Get snode error [{e}]");
                        return Ok(Status::SnodeError(e.to_string()))
                    }
                    log::debug!("get_snode({}) failed {e} attempt {i}/5", peer.peer.address);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        };
        if let Some(snode) = &snode {
            if let Some(require_snode) = &self.server.config.ptest.require_snode {
                if snode != require_snode {
                    log::debug!("[{id}] [{sa}] Wrong snode, want [{require_snode}] got [{snode}]");
                    return Ok(Status::WrongSnode);
                    // bail!("Snode does not match required snode");
                }
            }
        } else {
            log::debug!("[{id}] [{sa}] No snode");
            return Ok(Status::NoSnode);
            // bail!("Peer does not have an snode");
        }
        log::debug!("[{id}] [{sa}] Peer OK");

        Ok(Status::Ok)
    }

    async fn run(mut self) {
        loop {
            let Some(msg) = self.server.receiver.lock().await.recv().await else {
                log::info!("[{}] Recv got a None, shutting down", self.id);
                return;
            };
            let mut i = 0;
            let res = loop {
                i += 1;
                let res = tokio::select! {
                    res = self.test(&msg) => {
                        // Attempt to remove all connections from this test
                        let _ = self.server.cjdns.remove_conns(Some(self.id)).await;
                        match res {
                            Ok(Status::Ok) => break Status::Ok,
                            Ok(x) => x,
                            Err(e) => Status::Other(e.to_string()),
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(60*5)) => {
                        log::info!("[{}] timed out testing (attempt [{i}])", self.id);
                        Status::Other("Test function timed out".to_string())
                    }
                };
                if i > 3 {
                    break res;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            };
            if self.server.responder.send((msg,res)).await.is_err() {
                log::info!("[{}] send() was an error, shutting down", self.id);
                return;
            }
        }
    }
}

async fn main_loop_cycle(
    server: &Arc<Server>,
    send_task: &Sender<SeederListPeer>,
    recv_resp: &mut Receiver<(SeederListPeer,Status)>,
    currently_testing: &mut VecDeque<(String,u64)>,
) -> Result<()> {
    log::debug!("[MAIN] loop getting nodes");
    let peers = fetch_snode_data(&server.config.ptest.snode).await?;
    *server.state.lock().await = peers.clone();
    let nows = now_sec();
    while let Some((_, since)) = currently_testing.front() {
        if *since > nows - 60*20 {
            break;
        }
        currently_testing.pop_front();
    }
    for peer in peers {
        if peer.last_check_sec + server.config.ptest.retest_after_minutes*60 > nows {
            continue;
        }
        if currently_testing.iter().find(|(p,_)|p == &peer.peer.address).is_some() {
            continue;
        }
        log::debug!("[MAIN] Send {} for testing", peer.peer.address);
        currently_testing.push_back((peer.peer.address.clone(), nows));
        send_task.send(peer).await?;
    }

    let mut nodes = Vec::new();
    while let Ok((slp, stat)) = recv_resp.try_recv() {
        let pk = PublicKey::try_from(&slp.peer.public_key[..])?;
        let ip6 = CJDNS_IP6::try_from(&pk)?;
        log::debug!("[MAIN] Recv {} = {:?}", slp.peer.address, stat);
        nodes.push(SeederTestResNode{
            addr: slp.peer.address.parse()?,
            ip6: ip6.to_string(),
            error: if stat != Status::Ok {
                Some(format!("{:?}", stat))
            } else {
                None
            },
        })
    }
    if nodes.is_empty() {
        log::debug!("[MAIN] Nothing to post back");
        return Ok(());
    }
    log::debug!("[MAIN] Posting back [{}] results", nodes.len());
    post_snode_testres(&server.config.ptest.snode, &SeederTestRes{
        passwd: server.config.ptest.snode.pass.clone(),
        nodes,
    }).await?;
    log::debug!("[MAIN] Success");
    Ok(())
}

struct Server {
    cjdns: Cjdns,
    config: Config,
    receiver: Mutex<Receiver<SeederListPeer>>,
    responder: Sender<(SeederListPeer,Status)>,
    state: Mutex<Vec<SeederListPeer>>,
}

#[derive(Serialize,Deserialize)]
struct HttpStatusPeer {
    last_check_sec: u64,
    last_report_sec: u64,
    ring: u32,
    check_error: Option<String>,
    public_key: String,
    address: String,
    peer_id: String,
}

async fn http_status(server: Arc<Server>) -> HttpReply {
    let out = server.state.lock().await.iter().map(|p|HttpStatusPeer{
        last_check_sec: p.last_check_sec,
        last_report_sec: p.last_report_sec,
        ring: p.ring,
        check_error: p.check_error.clone(),
        public_key: p.peer.public_key.clone(),
        address: "REDACTED".into(),
        peer_id: p.id.clone(),
    }).collect::<Vec<_>>();
    json_reply(out)
}

async fn httpd(server: Arc<Server>) {
    let server1 = Arc::clone(&server);
    let api = warp::path!("api" / "v1" / "status")
        .and(warp::get())
        .and(warp::any().map(move || server1.clone()))
        .and_then(http_status);
    
    log::debug!("HTTP Server binding {}", server.config.ptest.http_bind);
    warp::serve(api).run(server.config.ptest.http_bind).await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Load the configuration from a file
    let config = load_config("config.yaml").await?;

    let cjdns = Cjdns::new(&config.ptest.cjdns_admin).await?;

    log::debug!("[MAIN] Delete all connections");
    cjdns.remove_conns(None).await?;

    let (send_task, receiver) = channel(512);
    let (responder, mut recv_resp) = channel(512);

    let server = Arc::new(Server{
        cjdns,
        config,
        receiver: Mutex::new(receiver),
        state: Default::default(),
        responder,
    });

    for id in 0..server.config.ptest.parallel_tests {
        tokio::task::spawn(TestAgent{
            id,
            server: Arc::clone(&server),
        }.run());
    }
    log::info!("Startup with {} parallel tasks", server.config.ptest.parallel_tests);

    tokio::task::spawn(httpd(Arc::clone(&server)));

    // Main thread calls the snode
    let mut currently_testing = VecDeque::new();
    loop {
        match main_loop_cycle(&server, &send_task, &mut recv_resp, &mut currently_testing).await {
            Ok(()) => {
                tokio::time::sleep(Duration::from_secs(20)).await;
            }
            Err(e) => {
                println!("Error in main loop: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
