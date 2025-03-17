//! UDP connection to the CJDNS Router.

use std::convert::TryFrom;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bencode::object::{Dict, Object, Get};
use cjdns_bytes::message::Message;
use eyre::eyre;
use sodiumoxide::crypto::hash::sha256::hash;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time;

use crate::errors::{ConnOptions, Error};
use crate::func_list::Funcs;
use crate::txid::Counter;
use crate::ConnectionOptions;

const PING_TIMEOUT: Duration = Duration::from_millis(1_000);
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10_000);

/// Admin connection to the CJDNS node.
///
/// Cloneable: cloned connection uses same underlying UDP socket and is thread-safe.
#[derive(Clone)]
pub struct Connection {
    socket: Arc<Mutex<UdpSocket>>,
    password: String,
    counter: Arc<Counter>,

    /// List of available remote functions.
    pub functions: Funcs,
}

impl Connection {
    pub(super) async fn new(opts: ConnectionOptions) -> Result<Self, Error> {
        let mut conn = Connection {
            socket: Arc::new(Mutex::new(create_udp_socket_sender(&opts.addr, opts.port).await?)),
            password: opts.password.clone(),
            counter: Arc::new(Counter::new_random()),
            functions: Funcs::default(),
        };

        conn.probe_connection(opts).await?;
        let fns = conn.load_available_functions().await?;
        conn.functions = fns;

        Ok(conn)
    }

    async fn probe_connection(&mut self, opts: ConnectionOptions) -> Result<(), Error> {
        self.call_func("ping", Dict::new(), true, PING_TIMEOUT)
            .await
            .map_err(|_| Error::ConnectError(ConnOptions::wrap(&opts)))?;

        if !self.password.is_empty() {
            self.call_func("AuthorizedPasswords_list", Dict::new(), false, DEFAULT_TIMEOUT)
                .await
                .map_err(|_| Error::AuthError(ConnOptions::wrap(&opts)))?;
        }

        Ok(())
    }

    async fn load_available_functions(&mut self) -> Result<Funcs, Error> {
        let mut res = Funcs::new();

        for i in 0.. {
            let mut args = Dict::new();
            args.insert("page", i);
            let ret = self.call_func(
                "Admin_availableFunctions",
                args,
                false,
                DEFAULT_TIMEOUT
            ).await?;
            let funcs =
                ret.get_dict("availableFunctions")
                .map_err(|e|Error::Protocol(eyre!("Failed getting availableFunctions {e}")))?;

            if funcs.is_empty() {
                break; // Empty answer - no more pages
            }

            res.add_funcs(funcs).map_err(|e|Error::Protocol(e))?;
        }

        Ok(res)
    }

    /// Call remote function on CJDNS router
    pub async fn invoke(&mut self, remote_fn_name: &str, args: Dict<'_>) -> Result<Dict<'static>, Error> {
        self.call_func(remote_fn_name, args, false, DEFAULT_TIMEOUT).await
    }

    async fn call_func(&mut self, remote_fn_name: &str, args: Dict<'_>, disable_auth: bool, timeout: Duration) -> Result<Dict<'static>, Error> {
        let call = async {
            if disable_auth || self.password.is_empty() {
                self.call_func_no_auth(remote_fn_name, args).await
            } else {
                self.call_func_auth(remote_fn_name, args).await
            }
        };
        time::timeout(timeout, call).await.map_err(|_| Error::TimeOut(timeout))?
    }

    async fn call_func_no_auth(&mut self, remote_fn_name: &str, args: Dict<'_>) -> Result<Dict<'static>, Error> {
        let txid = self.counter.next().to_string();
        let mut msg = Dict::new();
        msg.insert("txid", &txid);
        msg.insert("q", remote_fn_name);
        msg.insert("args", args);

        let resp = Dict::try_from(self.send_msg(msg).await?)
            .map_err(|e|Error::Protocol(eyre!("Error receiving from cjdns {e}")))?;
        check_txid(&txid, &resp)?;
        check_remote_error(&resp)?;

        Ok(resp)
    }

    async fn call_func_auth(&mut self, remote_fn_name: &str, args: Dict<'_>) -> Result<Dict<'static>, Error> {
        // Ask cjdns for a cookie first
        let new_cookie = {
            let resp = self.call_func_no_auth("cookie", Dict::new()).await?;
            resp.try_get_str("cookie")
                .map_err(|e|Error::Protocol(eyre!("Error getting cookie: {e}")))?
                .ok_or_else(||Error::Protocol(eyre!("cookie missing")))?
                .to_string()
        };

        // Hash password with salt
        let passwd_hash = {
            let cookie_passwd = self.password.clone() + &new_cookie;
            let digest = hash(cookie_passwd.as_bytes());
            hex::encode(digest)
        };

        let txid = self.counter.next().to_string();

        // Prepare message with initial hash
        let mut req = Dict::new();
        req.insert("txid", &txid);
        req.insert("q", "auth");
        req.insert("aq", remote_fn_name);
        req.insert("args", args);
        req.insert("cookie", new_cookie);
        req.insert("hash", passwd_hash);

        // Update message's hash
        let msg_hash = {
            let mut msg = Message::new();
            cjdns_bencode::standard::serialize(&mut msg, &Object::from(req.clone()), 0)
                .map_err(|e|Error::Protocol(e))?;
            let digest = hash(&msg.as_vec());
            hex::encode(digest)
        };
        req.insert("hash", msg_hash);

        // Send/receive
        let resp = self.send_msg(req).await?;
        check_txid(&txid, &resp)?;
        check_remote_error(&resp)?;

        Ok(resp)
    }

    async fn send_msg(&mut self, req: Dict<'_>) -> Result<Dict<'static>, Error>
    {
        // Send encoded request
        let mut msg = Message::new();
        cjdns_bencode::standard::serialize(&mut msg, &Object::from(req), 0)
            .map_err(|e|Error::Protocol(e))?;
        //dbg!(String::from_utf8_lossy(&msg));
        let socket = self.socket.lock().await;
        socket.send(&msg.as_vec()).await.map_err(|e| Error::NetworkOperation(e))?;

        // MTU of loopback
        let mut buf = [0; 65535];

        // Reseive encoded response synchronously
        let received = socket.recv(&mut buf).await.map_err(|e| Error::NetworkOperation(e))?;
        msg.clear();
        msg.write_all(&buf[..received])
            .map_err(|e|Error::NetworkOperation(e))?;
        //dbg!(String::from_utf8_lossy(&response));

        // Decode response
        let res = cjdns_bencode::standard::Parser::<
            32,
            true
        >::parse(&mut msg)
            .map_err(|e|{
                Error::Protocol(eyre::eyre!("Error parsing response: {}, response: {}",
                    e, String::from_utf8_lossy(&buf[..received])))
            })?;
        let res = res.into_dict()
            .map_err(|_|Error::Protocol(eyre::eyre!("Response not a dict, response: {}",
                String::from_utf8_lossy(&buf[..received]))))?;

        Ok(res.into_owned())
    }
}

async fn create_udp_socket_sender(addr: &str, port: u16) -> Result<UdpSocket, Error> {
    let ip_addr = addr.parse::<IpAddr>().map_err(|e| Error::BadNetworkAddress(e))?;
    let remote_address = SocketAddr::new(ip_addr, port);

    let local_address = "0.0.0.0:0";
    let socket = UdpSocket::bind(local_address).await.map_err(|e| Error::NetworkOperation(e))?;
    socket.connect(&remote_address).await.map_err(|e| Error::NetworkOperation(e))?;

    Ok(socket)
}

#[inline]
fn check_txid(sent_txid: &String, received: &Dict<'_>) -> Result<(), Error> {
    let received_txid = received.try_get_str("txid")
        .map_err(|e|Error::Protocol(eyre!("Error getting txid {e}")))?
        .ok_or_else(||Error::Protocol(eyre!("txid missing")))?;
    if sent_txid == &received_txid {
        Ok(())
    } else {
        Err(Error::BrokenTx {
            sent_txid: sent_txid.clone(),
            received_txid: received_txid.to_string(),
        })
    }
}

fn check_remote_error(received: &Dict<'_>) -> Result<(), Error> {
    let remote_error_msg = received.try_get_str("error")
        .map_err(|e|Error::Protocol(eyre!("Error getting error field: {e}")))?;
    let Some(remote_error_msg) = remote_error_msg else {
        return Ok(());
    };
    if remote_error_msg.is_empty() || remote_error_msg.eq_ignore_ascii_case("none") {
        Ok(())
    } else {
        Err(Error::RemoteError(remote_error_msg.to_string()))
    }
}
