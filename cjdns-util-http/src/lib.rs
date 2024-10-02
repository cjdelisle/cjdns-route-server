use std::convert::Infallible;

use serde::Serialize;
use warp::hyper::StatusCode;

pub type HttpReply = Result<Box<dyn warp::Reply>, Infallible>;

pub fn status_resp<T: Into<String>>(msg: T, status_code: StatusCode) -> HttpReply {
    Ok(Box::new(warp::reply::with_status(msg.into(), status_code)))
}

pub fn internal_err(msg: &str, e: anyhow::Error) -> HttpReply {
    status_resp(format!("{msg}: {e}"), StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn forbidden<T: Into<String>>(msg: T) -> HttpReply {
    status_resp(msg, StatusCode::FORBIDDEN)
}

pub fn json_reply<T>(t: T) -> HttpReply
where
    T: Serialize,
{
    Ok(match serde_json::to_string_pretty(&t) {
        Err(_) => Box::new(warp::reply::with_status(
            "unable to serialize reply",
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
        Ok(v) => Box::new(
            warp::http::response::Builder::new()
                .header("Content-Type", "application/json")
                .body(v),
        ),
    })
}
