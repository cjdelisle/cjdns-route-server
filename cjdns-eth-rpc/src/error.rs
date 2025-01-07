use std::sync::Arc;

use alloy::transports::{RpcError, TransportErrorKind};
use eyre::{bail, Result};

use crate::rpcinstance::RpcInfo;

pub fn handle_transport_error(
    t: &RpcError<TransportErrorKind>,
    i: i32,
    rpc_max_tries: i32,
) -> Result<String> {
    let out = match t {
        RpcError::UnsupportedFeature(x) => {
            bail!("UnsupportedFeature({x})");
        }
        RpcError::ErrorResp(x) => {
            bail!("Error Response: {} {} {:?}", x.message, x.code, x.data);
        }
        RpcError::NullResp => {
            "NullResponse".into()
        }
        RpcError::LocalUsageError(x) => {
            bail!("LocalUsageError({})", x);
        }
        RpcError::SerError(x) => {
            bail!("SerError({})", x);
        }
        RpcError::DeserError{ err, text } => {
            format!("DeserError({}, {})", err, text)
        }
        RpcError::Transport(t) => {
            match t {
                TransportErrorKind::MissingBatchResponse(x) => {
                    format!("MissingBatchResponse({:?})", x)
                }
                TransportErrorKind::BackendGone => {
                    bail!("BackendGone");
                },
                TransportErrorKind::PubsubUnavailable => {
                    bail!("PubsubUnavailable");
                }
                TransportErrorKind::HttpError(h) => {
                    format!("HttpError({h:?})")
                }
                TransportErrorKind::Custom(c) => {
                    format!("CustomTransportError({})", c)
                }
                _ => {
                    format!("Unknown transport error {:?}", t)
                }
            }
        }
    };
    if i > rpc_max_tries {
        bail!("Failed after {rpc_max_tries} tries");
    } else {
        println!("try_do_eth() rpc error {i}/{rpc_max_tries}, retry...");
    }
    Ok(out)
}

pub async fn handle_generic_error(
    e: eyre::Error,
    i: i32,
    rpc_info: &Arc<RpcInfo>,
    rpc_max_tries: i32,
) -> Result<()> {
    let cause = if let Some(re) =
        e.chain()
        .filter_map(|er|er.downcast_ref::<RpcError<TransportErrorKind>>())
        .next()
    {
        handle_transport_error(re, i, rpc_max_tries)
    } else {
        return Err(e);
    };
    rpc_info.set_dead(&format!("{:?}", cause)).await;
    Ok(())
}