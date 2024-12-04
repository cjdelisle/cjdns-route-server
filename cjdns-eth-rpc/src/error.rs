use std::sync::Arc;

use alloy::transports::{RpcError, TransportErrorKind};
use anyhow::{bail, Result};

use crate::{rpcinstance::RpcInfo, types::RPC_MAX_TRIES};

pub fn handle_transport_error(
    t: &RpcError<TransportErrorKind>,
    i: i32,
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
    if i > RPC_MAX_TRIES {
        bail!("Failed after {RPC_MAX_TRIES} tries");
    } else {
        println!("try_do_eth() rpc error {i}/{RPC_MAX_TRIES}, retry...");
    }
    Ok(out)
}

pub async fn handle_generic_error(
    e: anyhow::Error,
    i: i32,
    rpc_info: &Arc<RpcInfo>,
) -> Result<()> {
    let cause = if let Some(re) =
        e.chain()
        .filter_map(|er|er.downcast_ref::<RpcError<TransportErrorKind>>())
        .next()
    {
        handle_transport_error(re, i)?
    } else {
        return Err(e);
    };
    rpc_info.set_dead(&cause).await;
    Ok(())
}