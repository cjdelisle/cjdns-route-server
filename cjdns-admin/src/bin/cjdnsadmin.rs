//! CJDNS Admin tool

use std::{env, path};

use cjdns_bencode::{json, object::{Dict, Object}};
use cjdns_bytes::message::Message;
use eyre::Error;
use regex::Regex;

use cjdns_admin::Func;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);
    }
}

async fn run() -> Result<(), Error> {
    let mut cjdns = cjdns_admin::connect(None).await?;

    let args = env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        let bin_path: path::PathBuf = env::args_os().next().expect("missing binary name (bad OS?)").into();
        let bin_name = bin_path.file_name().expect("missing file name").to_string_lossy();
        eprintln!("Usage: {} 'ping()' ## For example to send a ping request", bin_name);
        eprintln!("List of available RPC requests with parameters is as follows:");
        eprintln!("{}", cjdns.functions)
    } else {
        let fn_call_str = args.last().cloned().ok_or_else(|| Error::msg("empty program args"))?;

        let (fn_name, fn_args) = split_fn_invocation_str(&fn_call_str).map_err(|_| Error::msg("bad function invocation expression"))?;

        let fn_args = parse_remote_fn_args(&fn_args).map_err(|_| Error::msg("bad function arguments"))?;

        let func = cjdns.functions.find(&fn_name).ok_or_else(|| Error::msg("unknown function name"))?;
        let fn_args = make_args(func, fn_args);

        let res = cjdns.invoke(&fn_name, fn_args).await?;
        let mut msg = Message::new();
        json::serialize(&mut msg, &Object::from(res))
            .map_err(|_| Error::msg("failed to serialize response"))?;
        println!("{}", String::from_utf8(msg.as_vec())?);
    };

    // Client disconnects automatically when `cjdns` drops out of scope

    Ok(())
}

fn split_fn_invocation_str(s: &str) -> Result<(String, String), ()> {
    // Regexp for function invocation, e.g. `foo_func(42, "ololo")`, captures func name and arg list.
    let re_fn_call = Regex::new(r"([\w]+)\(([^)]*)\)").expect("bad regex");

    let caps = re_fn_call.captures(s).ok_or(())?;
    let name = caps.get(1).ok_or(())?.as_str().to_string();
    let args = caps.get(2).ok_or(())?.as_str().to_string();

    Ok((name, args))
}

fn parse_remote_fn_args(s: &str) -> Result<Vec<Object<'static>>, ()> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut fn_args = Vec::new();
    for arg in s.split(",").map(str::trim) {
        let arg = match arg.chars().next().ok_or(())? {
            '-' | '0'..='9' => {
                let value: i64 = arg.parse().map_err(|_| ())?;
                value.into()
            }
            '"' => {
                let n = arg.len();
                if n < 2 || arg.chars().last().ok_or(())? != '"' {
                    return Err(()); // Bad string argument - unpaired quotes
                }
                arg[1..n - 1].to_string().into()
            }
            _ => return Err(()), // Bad argument - unknown type
        };
        fn_args.push(arg);
    }
    Ok(fn_args)
}

fn make_args(func: &Func, arg_values: Vec<Object<'static>>) -> Dict<'static> {
    let mut args = Dict::new();
    for (arg, arg_value) in func.args.iter().zip(arg_values) {
        // Here we won't check argument types, required or not etc.
        // Let the remote side do all necessry checks and return error if needed.
        args.insert(arg.name.clone(), arg_value);
    }
    args
}