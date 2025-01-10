use std::sync::Arc;

use alloy::transports::{RpcError, TransportError, TransportErrorKind};
use eyre::{bail, Result};

use crate::rpcinstance::RpcInfo;

pub fn handle_transport_error(
    t: &TransportError,
    i: i32,
    rpc_max_tries: i32,
) -> Result<String> {
    let out = match t {
        RpcError::UnsupportedFeature(x) => {
            bail!("UnsupportedFeature({x})");
        }
        RpcError::ErrorResp(x) => {
            // Error running cycle() -> Error Response: nonce too low: next nonce 285919, tx nonce 285918 3 None
            if x.is_retry_err() || x.message.contains("nonce too low") {
                format!("ErrorResp {} {} {:?}", x.message, x.code, x.data)
            } else {
                bail!("Error Response: {} {} {:?}", x.message, x.code, x.data);
            }
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
    let cause = if let Some(e) =
        e.chain()
        .filter_map(|er|er.downcast_ref::<alloy::contract::Error>())
        .next()
    {
        match e {
            alloy::contract::Error::TransportError(e) => {
                Some(handle_transport_error(e, i, rpc_max_tries))
            }
            _ => {
                None
            }
        }
    } else {
        None
    };
    if let Some(cause) = cause {
        // Throw if handle_transport_error thinks it's our fault
        let cause = cause?;
        rpc_info.set_dead(&cause).await;
    } else {
        return Err(e);
    }
    Ok(())
}