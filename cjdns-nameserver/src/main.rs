use std::{
    collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::{Arg, Command, parser::ValuesRef};
use config::NameserverConfig;
use hickory_client::{client::{Client, SyncClient}, rr::{rdata::{AAAA, NS, SOA}, Name, RecordData}, udp::UdpClientConnection};
use hickory_server::{
    authority::{Catalog, MessageResponseBuilder},
    proto::{
        op::{Header, ResponseCode},
        rr::{
            self, rdata::A, Record, RecordType,
        }
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture
};
use rand::Rng;
use tokio::{net::UdpSocket, sync::RwLock};

use cjdns_eth_rpc::EthRpc;
use cjdns_bytes::{dnsseed::{CjdnsPeer, CjdnsTxtRecord}, message::Message};
use cjdns_keys::CJDNSPublicKey;

mod config;

async fn listen_dns() -> Result<()> {
    let config = tokio::fs::read_to_string("./nameserver.yaml").await
        .context("Failed to read config: nameserver.yaml")?;
    let config: NameserverConfig = serde_yaml::from_str(&config)?;
    let sock = UdpSocket::bind(config.bind_ipv4).await?;

    let eth_rpc = cjdns_eth_rpc::EthRpc::new(&config.rpc).await?;

    let mut catalog = Catalog::new();
    // // for (domain, records) in config.zones().iter() {
    //     let zone = rr::Name::parse("pkt.wiki.", None)?;
    //     let ns = rr::Name::parse("loopy.pkteer.com.", None)?;
    //     let mut authorities = InMemoryAuthority::empty(zone.clone(), ZoneType::Primary, false);
    //     // for record in records.iter() {
    //         // let r = record.try_into()?;
    //         let mut r = Record::with(zone.clone(), RecordType::NS, 5);
    //         r.set_data(Some(NS(ns.clone()).into_rdata()));
    //         // r.set_data(rdata)
    //         authorities.upsert_mut(r, 0);
    //     // }
    //     catalog.upsert(zone.clone().into(), Box::new(Arc::new(authorities)));
    // // }

    let catalog = Arc::new(RwLock::new(catalog));
    let handler = ReqHandler::new(catalog, config, eth_rpc)?;
    let mut sf = ServerFuture::new(handler);
    sf.register_socket(sock);

    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;

    Ok(())
}

impl ReqHandler {
    fn new(catalog: Arc<RwLock<Catalog>>, config: NameserverConfig, eth_rpc: Arc<EthRpc>) -> Result<ReqHandler> {
        let name = rr::Name::parse(&config.my_name, None)
            .with_context(||format!("nameserver.yaml error: Unable to parse {} as a domain", config.my_name))?;
        let my_ipv4 = Record::from_rdata(
            name.clone(),
            500,
            A(config.public_ipv4.clone()).into_rdata()
        );
        let my_ipv6 = config.public_ipv6.map(|public_ipv6|{
            let mut rec = Record::from_rdata(
                name.clone(),
                500,
                AAAA(public_ipv6.clone()).into_rdata()
            );
            rec.set_record_type(RecordType::AAAA);
            rec
        });
        let mut nameservers = Vec::new();
        for ns in &config.nameservers {
            nameservers.push(
                rr::Name::parse(ns, None)
                    .with_context(||format!("nameserver.yaml error: Unable to parse {} as a domain", ns))?
            );
        }
        Ok(Self {
            m: RwLock::new(ReqHandlerMut{
                records: Default::default(),
                nameservers,
            }),
            catalog,
            my_ipv4,
            my_ipv6,
            eth_rpc,
        })
    }
}

#[derive(Default)]
struct ReqHandlerMut {
    records: HashMap<(String,RecordType),Vec<Record>>,
    nameservers: Vec<Name>,
}

struct ReqHandler {
    m: RwLock<ReqHandlerMut>,
    catalog: Arc<RwLock<Catalog>>,
    my_ipv4: Record,
    my_ipv6: Option<Record>,
    eth_rpc: Arc<EthRpc>,
}

async fn respond_with_records<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    answers: Vec<&Record>,
    name_servers: Vec<&Record>,
    soa: Vec<&Record>,
) -> Result<ResponseInfo> {
    let resp =
        MessageResponseBuilder::from_message_request(request).build(
            Header::response_from_request(request.header()),
            answers,
            name_servers,
            soa,
            &[], // additional
        );
    match response_handle.send_response(resp).await {
        Ok(x) => {
            Ok(x)
        }
        Err(e) => {
            println!("Error crafting A response: {e}");
            Err(e.into())
        }
    }
}

fn serve_failed() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::ServFail);
    header.into()
}

fn nxdomain() -> ResponseInfo {
    let mut header = Header::new();
    header.set_response_code(ResponseCode::NXDomain);
    header.into()
}

fn extract_subdomains(domain: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 && parts[parts.len() - 2].eq_ignore_ascii_case("pkt") {
        Some(parts
            .into_iter()
            .filter(|&part| !part.eq_ignore_ascii_case("pkt"))
            .map(|part| part.to_string())
            .collect())
    } else {
        None
    }
}

#[async_trait::async_trait]
impl RequestHandler for ReqHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let name = query.name().to_string();
        println!("Query of type {} for {name}", query.query_type());

        // Self-request for our own IP
        if query.query_type() == RecordType::A || query.query_type() == RecordType::AAAA &&
            name.ends_with(&self.my_ipv4.name().to_ascii())
        {
            let mut recs = if query.query_type() == RecordType::A {
                vec![self.my_ipv4.clone()]
            } else if query.query_type() == RecordType::AAAA {
                if let Some(ip6) = &self.my_ipv6 {
                    vec![ip6.clone()]
                } else {
                    Vec::new()
                }
            } else {
                unreachable!()
            };
            for r in &mut recs {
                r.set_name(query.name().into());
            }
            return if let Ok(res) = respond_with_records(
                request,
                response_handle,
                recs.iter().collect(),
                Vec::new(),
                Vec::new(),
            ).await {
                res
            } else {
                serve_failed()
            };
        } else if query.query_type() == RecordType::SOA &&
            query.name().num_labels() == 2 &&
            name.starts_with("pkt.")
        {
            let soa = Record::from_rdata(
                query.name().into(),
                600,
                SOA::new(
                    query.name().into(),
                    Name::parse("domains.blockchain.project.pkt.", None).unwrap(),
                    2024120300,
                    3600,
                    7200,
                    604800,
                    300,
                ).into_rdata(),
            );
            return if let Ok(res) = respond_with_records(
                request,
                response_handle,
                Vec::new(),
                Vec::new(),
                vec![&soa],
            ).await {
                res
            } else {
                serve_failed()
            };
        } else if query.query_type() == RecordType::NS &&
            query.name().num_labels() == 2 &&
            name.starts_with("pkt.")
        {
            let names = {
                let m = self.m.read().await;
                m.nameservers.clone()
            };
            let recs = names.into_iter().map(|n|Record::from_rdata(
                query.name().into(),
                600,
                NS(n).into_rdata(),
            )).collect::<Vec<_>>();
            return if let Ok(res) = respond_with_records(
                request,
                response_handle,
                Vec::new(),
                recs.iter().collect(),
                Vec::new(),
            ).await {
                res
            } else {
                serve_failed()
            };
        } else if let Some(mut path) = extract_subdomains(&name) {
            // my.project.pkt.xyz
            // ["my","project","xyz"]
            if path.len() == 1 {
                // We need to map pkt.xxx to whatever domain the owner of .xxx wants
                return nxdomain();
            }
            // We don't care what the top level domain is
            path.pop();
            let key = path.join(".");
            let mut recs = {
                let m = self.m.read().await;
                let Some(recs) = m.records.get(&(key,query.query_type())) else {
                    return nxdomain();
                };
                recs.clone()
            };
            for r in &mut recs {
                r.set_name(query.name().into());
            }
            return if let Ok(res) = respond_with_records(
                request,
                response_handle,
                recs.iter().collect(),
                Vec::new(),
                Vec::new(),
            ).await {
                res
            } else {
                serve_failed()
            };
        }

        // If it's not an NS query or doesn't match the pattern, pass it to the catalog
        self.catalog
            .read()
            .await
            .handle_request(request, response_handle)
            .await
    }
}

async fn async_main() -> Result<()> {
    let matches = Command::new("Cjdnseed")
        .about("A tool to generate peering credentials")
        .subcommand(
            Command::new("generate")
                .about("Generates credentials for a node")
                .arg(
                    Arg::new("ip_port")
                        .help("The public IP address and port number of the node")
                        .required(true),
                )
                .arg(
                    Arg::new("index")
                        .help("The number of the generated credential")
                        .required(true),
                )
                .arg(
                    Arg::new("pubkey")
                        .help("The public key of the node to make peering credentials for")
                        .required(true),
                )
                .arg(
                    Arg::new("version")
                        .help("The protocol version of the node")
                        .required(true),
                )
                .arg(
                    Arg::new("pass")
                        .help("The base64 password code, allowing you to re-generate the exact same code twice")
                        .long("pass")
                        .required(false)
                )
        )
        .subcommand(
            Command::new("txtrec")
                .about("Create a DNS TXT record")
                .arg(
                    Arg::new("snode")
                        .help("The Route Server pubkey that should be used")
                        .required(true),
                )
                .arg(
                    Arg::new("peer")
                        .help("An encoded peer credential")
                        .num_args(1..)
                        .required(true),
                )
        )
        .subcommand(
            Command::new("testseed")
                .about("Test a DNS seed by requesting and parsing it's record")
                .arg(
                    Arg::new("seed")
                        .help("The seed node to test")
                        .required(true),
                )
        )
        .subcommand(
            Command::new("serve")
                .about("Start domain server")
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("generate") {
        let ip_port: &String = matches.get_one("ip_port").expect("missing ip_port");
        let index: &String = matches.get_one("index").expect("Missing index");
        let pubkey: &String = matches.get_one("pubkey").expect("Missing pubkey");
        let version: &String = matches.get_one("version").expect("Missing version");
        let pass: Option<&String> = matches.get_one("pass");

        let ip_port: SocketAddr = ip_port.parse().context("ip_port could not be parsed")?;
        let index: u16 = index.parse().context("index must be an unsigned number between 0 and 65535")?;
        let version: u32 = version.parse().context("Version must be a u32")?;
        let pubkey = CJDNSPublicKey::try_from(&pubkey[..])
            .context("pubkey not a valid cjdns public key")?;

        let mut rng = rand::thread_rng();
        let mut p = CjdnsPeer{
            address: ip_port,
            pubkey: pubkey.raw().clone(),
            login: index,
            password: rng.gen(),
            version,
        };

        if let Some(pass) = pass {
            let x = STANDARD_NO_PAD.decode(pass)
                .and_then(|pass|{
                    if pass.len() != 8 { Err(base64::DecodeError::InvalidLength) } else { Ok(pass) } 
                })
                .context("If specified --pass must be 8 bytes encoded as base64")?;
            p.password.copy_from_slice(&x[..]);
        }

        let pl = p.peering_line();
        println!(r#"Peering Line: "{}":{{"login":"{}","password":"{}","publicKey":"{}"}},"#,
            pl.address,
            pl.login,
            pl.password,
            pl.public_key,
        );
        
        let ap = p.authorized_password();
        println!(r#"Authorized Password: {{"user":"{}","password":"{}"}},"#,
            ap.user,
            ap.password,
        );

        let mut msg = Message::new();
        p.encode(&mut msg)?;
        let encoded = hex::encode(msg.as_vec());
        println!("Encoded peering cred: {}", encoded);
    } else if let Some(matches) = matches.subcommand_matches("txtrec") {
        let snode: &String = matches.get_one("snode").expect("Missing snode");
        let snode =
            CJDNSPublicKey::try_from(&snode[..]).context("Unable to parse snode address")?;
        let peers: ValuesRef<String> = matches.get_many("peer").expect("Missing peer");
        println!("Snode is {snode}");
        let mut decoded_peers = Vec::new();
        for ps in peers {
            let tlv = hex::decode(&ps[..])
                .with_context(||format!("Unable to decode {ps} as hex"))?;
            if tlv.len() < 2 {
                anyhow::bail!("Peer {ps} must be more than 2 bytes");
            }
            let p = CjdnsPeer::decode(tlv[0], &mut &tlv[2..])
                .with_context(||format!("Unable to decode {ps} as a CjdnsPeer"))?;
            decoded_peers.push(p);
        }
        let ctr = CjdnsTxtRecord{
            snode_pubkey: Some(snode.raw().clone()),
            peers: decoded_peers,
            peer_id: None,
            unknown_records: Vec::new(),
        };
        println!("TXT {}", ctr.encode()?);
    } else if let Some(matches) = matches.subcommand_matches("testseed") {
        let seed: &String = matches.get_one("seed").expect("Missing seed");
        let address = "8.8.8.8:53".parse().unwrap();
        let conn = UdpClientConnection::new(address).unwrap();
        let resolver = SyncClient::new(conn);
        let seed = Name::from_str(&seed)?;
        let res = resolver.query(&seed, rr::DNSClass::IN, RecordType::TXT)
            .with_context(||format!("Failed dns lookup for {seed}"))?;
        let txt = res.answers().iter().next().ok_or_else(||anyhow!("No TXT records found"))?;
        let txt = txt.to_string();
        println!("TXT Record: {txt}");
        let ctr = CjdnsTxtRecord::decode(&txt)
            .with_context(||format!("Unable to decode seed TXT record {txt}"))?;

        if let Some(snode) = &ctr.snode_pubkey {
            let snode = CJDNSPublicKey::from(snode.clone());
            println!("Snode: {}", snode.to_string());
        }
        if !ctr.peers.is_empty() {
            println!("Peering Lines:");
            for peer in &ctr.peers {
                let pl = peer.peering_line();
                println!(r#"  "{}":{{"login":"{}","password":"{}","publicKey":"{}"}},"#,
                    pl.address,
                    pl.login,
                    pl.password,
                    pl.public_key,
                );
            }
        }
    } else if let Some(_) = matches.subcommand_matches("serve") {
        listen_dns().await?
    } else {
        println!("Not a valid command, try --help");
    }

    Ok(())
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("tokio-worker")
        .thread_stack_size(32 * 1024 * 1024)
        .enable_time()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async_main())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomains() {
        // Test cases where the function should return Some
        assert_eq!(extract_subdomains("abcd.pkt.xyz"), Some(vec!["abcd".to_string(), "xyz".to_string()]));
        assert_eq!(extract_subdomains("defg.hijk.pkt.com"), Some(vec!["defg".to_string(), "hijk".to_string(), "com".to_string()]));
        assert_eq!(extract_subdomains("pkt.com"), Some(vec!["com".to_string()]));

        // Test cases where the function should return None
        assert_eq!(extract_subdomains("example.com"), None);
        assert_eq!(extract_subdomains("test.pkt"), None); // Missing TLD after pkt
        assert_eq!(extract_subdomains("too.short"), None); // Not enough parts
        assert_eq!(extract_subdomains("pkt.example.com"), None); // "pkt" not at the second to last position
        assert_eq!(extract_subdomains("a.b.c.d.pkt"), None); // Needs a TLD after "pkt"
    }
}