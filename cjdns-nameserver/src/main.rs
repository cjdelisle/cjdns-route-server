use std::{
    net::{Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use eyre::{bail, eyre, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::{Arg, Command, parser::ValuesRef};
use config::NameserverConfig;
use hickory_client::{
    client::{Client, SyncClient},
    rr::{
        rdata::{AAAA, NS, SOA, TXT},
        Name,
        RecordData,
    },
    udp::UdpClientConnection,
};
use hickory_server::{
    authority::MessageResponseBuilder,
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
use seeder::Seeder;
use tokio::{net::UdpSocket, sync::RwLock};

use cjdns_eth_rpc::EthRpc;
use cjdns_bytes::{dnsseed::{CjdnsPeer, CjdnsTxtRecord}, message::Message};
use cjdns_keys::CJDNSPublicKey;
use cjdns_pns::{record, Pns};

mod config;
mod seeder;

async fn listen_dns() -> Result<()> {
    let config = tokio::fs::read_to_string("./nameserver.yaml").await
        .context("Failed to read config: nameserver.yaml")?;
    let config: NameserverConfig = serde_yaml::from_str(&config)?;
    let sock = UdpSocket::bind(config.bind_ipv4).await?;
    let sock6 = if let Some(bind_ipv6) = config.bind_ipv6 {
        Some(UdpSocket::bind(bind_ipv6).await?)
    } else {
        None
    };

    let eth_rpc = EthRpc::new(&config.rpc).await?;
    let pns = Pns::new(eth_rpc).await?;

    let handler = ReqHandler::new(config, pns)?;
    let mut sf = ServerFuture::new(handler);
    sf.register_socket(sock);
    if let Some(sock6) = sock6 {
        sf.register_socket(sock6);
    }

    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;

    Ok(())
}

impl ReqHandler {
    fn new(config: NameserverConfig, pns: Arc<Pns>) -> Result<ReqHandler> {
        let seeder = if let Some(seeder_cfg) = &config.seeder {
            Some(seeder::Seeder::new(seeder_cfg)?)
        } else {
            None
        };
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
        for (ns, ns_ipv4) in &config.nameservers {
            nameservers.push(
                (
                    rr::Name::parse(ns, None)
                        .with_context(||format!("nameserver.yaml error: Unable to parse {} as a domain", ns))?,
                    ns_ipv4.parse()
                        .with_context(||format!("nameserver.yaml error: Unable to parse {} as an IPv4", ns_ipv4))?,
                )
            );
        }
        Ok(Self {
            m: RwLock::new(ReqHandlerMut{
                nameservers,
            }),
            my_ipv4,
            my_ipv6,
            pns,
            config,
            seeder,
        })
    }
}

#[derive(Default)]
struct ReqHandlerMut {
    nameservers: Vec<(Name,Ipv4Addr)>,
}

struct ReqHandler {
    m: RwLock<ReqHandlerMut>,
    my_ipv4: Record,
    my_ipv6: Option<Record>,
    pns: Arc<Pns>,
    config: NameserverConfig,
    seeder: Option<Arc<Seeder>>,
}

async fn respond_with_records<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
    answers: Vec<&Record>,
    name_servers: Vec<&Record>,
    soa: Vec<&Record>,
    glue: Vec<&Record>,
) -> ResponseInfo {
    let mut hdr = Header::response_from_request(request.header());
    hdr.set_authoritative(true);
    let resp =
        MessageResponseBuilder::from_message_request(request).build(
            hdr,
            answers,
            name_servers,
            soa,
            glue, // additional
        );
    match response_handle.send_response(resp).await {
        Ok(x) => { x }
        Err(e) => {
            println!("Error crafting response: {e}");
            hdr.into()
        }
    }
}

async fn respond<R: ResponseHandler>(request: &Request, mut response_handle: R, code: ResponseCode) -> ResponseInfo {
    let mut hdr = Header::response_from_request(request.header());
    hdr.set_response_code(code);
    let resp =
        MessageResponseBuilder::from_message_request(request).build(
            hdr,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
    match response_handle.send_response(resp).await {
        Ok(x) => { x }
        Err(e) => {
            println!("Error crafting {code} response: {e}");
            hdr.into()
        }
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
        println!("Query of type {} for {name} from {}", query.query_type(), request.request_info().src);

        // Self-request for our own IP
        if name.ends_with(&self.my_ipv4.name().to_ascii()) {
            if query.query_type() == RecordType::A || query.query_type() == RecordType::AAAA {
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
                return respond_with_records(
                    request,
                    response_handle,
                    recs.iter().collect(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ).await;
            } else if name.starts_with("seed.") && query.query_type() == RecordType::TXT && self.seeder.is_some() {
                if let Some(seeder) = &self.seeder {
                    let seed = match seeder.get_seed_txt().await {
                        Ok(seed) => seed,
                        Err(e) => {
                            println!("Error getting seed: {e}");
                            return respond(request, response_handle, ResponseCode::ServFail).await;
                        }
                    };
                    let record = Record::from_rdata(
                        query.name().into(),
                        300,
                        TXT::new(vec![seed]).into_rdata(),
                    );
                    return respond_with_records(
                        request,
                        response_handle,
                        vec![&record],
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ).await;
                }
            } else {
                return respond(request, response_handle, ResponseCode::NoError).await
            }
        }
        
        if query.name().num_labels() == 2 && name.starts_with("pkt.") {
            if query.query_type() == RecordType::SOA {
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
                return respond_with_records(
                    request,
                    response_handle,
                    Vec::new(),
                    Vec::new(),
                    vec![&soa],
                    Vec::new(),
                ).await;
            } else if query.query_type() == RecordType::NS {
                let mut names = {
                    let m = self.m.read().await;
                    m.nameservers.clone()
                };
                if let Some(pfx) = self.config.special_ns_prefix.get(&name) {
                    for (n, _) in &mut names {
                        let Ok(local) = Name::from_str(pfx) else {
                            println!("{pfx} does not parse as a name");
                            continue;
                        };
                        let Ok(pn) = local.append_name(&n) else {
                            println!("Unable to prepend prefix {pfx} to name {n}");
                            continue;
                        };
                        *n = pn;
                    }
                }
                let recs = names.iter().map(|(n,_)|Record::from_rdata(
                    query.name().into(),
                    600,
                    NS(n.clone()).into_rdata(),
                )).collect::<Vec<_>>();
                let glue = names.iter().map(|(n,ip)|Record::from_rdata(
                    n.clone(),
                    600,
                    A(ip.clone()).into_rdata(),
                )).collect::<Vec<_>>();
                return respond_with_records(
                    request,
                    response_handle,
                    recs.iter().collect(),
                    Vec::new(),
                    Vec::new(),
                    glue.iter().collect(),
                ).await;
            } else {
                return respond(request, response_handle, ResponseCode::NoError).await;
            }
        }

        let nname: Name = query.name().into();
        match self.pns.get_records(&nname, query.query_type()).await {
            Err(e) => {
                println!("Error querying PNS: {e}");
                respond(request, response_handle, ResponseCode::ServFail).await
            }
            Ok(None) => {
                println!("Reply NXDOMAIN");
                respond(request, response_handle, ResponseCode::NXDomain).await
            }
            Ok(Some(recs)) => {
                println!("Reply records {}", recs.len());
                respond_with_records(
                    request,
                    response_handle,
                    recs.iter().collect(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ).await
            }
        }
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
            Command::new("record")
                .about("Create a binary encoded record from text")
                .arg(
                    Arg::new("record")
                        .help(concat!("The record text representation in the form of ",
                            "type:name:ttl:value e.g. A:example.com:300:1.2.3.4"))
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
                eyre::bail!("Peer {ps} must be more than 2 bytes");
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
        let txt = res.answers().iter().next().ok_or_else(||eyre!("No TXT records found"))?;
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
    } else if let Some(matches) = matches.subcommand_matches("record") {
        let recs = matches.get_many::<String>("record").expect("Missing record");
        let mut rv = Vec::new();
        for rec in recs {
            let parts: Vec<&str> = rec.split(':').collect();
            if parts.len() != 4 {
                bail!("Record must have 4 parts: type:name:ttl:value");
            }
            let r = record::JsonRecord{
                rtype: parts[0].to_string(),
                name: parts[1].to_string(),
                value: parts[3].to_string(),
                ttl_sec: parts[2].parse().expect("TTL must be a number"),
            };
            let r: Record = (&r).try_into().context("Unable to parse record")?;
            rv.push(r);
        }
        let enc = record::encode_records(&rv)?;
        println!("Encoded records: 0x{}", hex::encode(&enc));
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