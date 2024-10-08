//! CJDNS IP6

use std::convert::TryFrom;
use std::ops::Deref;

use regex::Regex;
use serde::{Serialize, Serializer};
use cjdns_crypto::hash::sha512;

use crate::{
    CJDNSPublicKey,
    errors::{KeyCreationError, Result},
    utils::{debug_fmt, slice_to_array16, vec_to_array16},
};

lazy_static! {
    static ref IP6_RE: Regex = Regex::new("^fc[0-9a-f]{2}:(?:[0-9a-f]{4}:){6}[0-9a-f]{4}$").expect("bad regexp");
}

/// CJDNS IP6 type
#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CJDNS_IP6 {
    k: [u8; 16],
}

impl CJDNS_IP6 {
    /// Size in bytes of the IPv6 address
    pub const SIZE: usize = 16;

    /// Valid CJDNS IPv6 must start with `0xFC` byte.
    const FIRST_BYTE: u8 = 0xFC;
}

impl TryFrom<&CJDNSPublicKey> for CJDNS_IP6 {
    type Error = KeyCreationError;

    fn try_from(value: &CJDNSPublicKey) -> Result<Self> {
        let pub_key_double_hash = sha512::hash(&sha512::hash(&value).0);
        Self::try_from(&pub_key_double_hash[..Self::SIZE])
    }
}

impl TryFrom<&[u8]> for CJDNS_IP6 {
    type Error = KeyCreationError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(KeyCreationError::InvalidLength);
        }
        if bytes[0] == Self::FIRST_BYTE || bytes == [0; Self::SIZE] {
            return Ok(CJDNS_IP6 { k: slice_to_array16(bytes) });
        }
        Err(KeyCreationError::ResultingIp6OutOfValidRange)
    }
}

impl TryFrom<&str> for CJDNS_IP6 {
    type Error = KeyCreationError;

    fn try_from(value: &str) -> Result<Self> {
        if IP6_RE.is_match(value) {
            let ip6_joined = value.split(":").collect::<String>();
            let ip6_bytes = hex::decode(ip6_joined).expect("invalid hex string");
            return Ok(CJDNS_IP6 { k: vec_to_array16(ip6_bytes) });
        }
        Err(KeyCreationError::BadString)
    }
}

impl Deref for CJDNS_IP6 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.k
    }
}

impl Serialize for CJDNS_IP6 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl std::fmt::Display for CJDNS_IP6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut ip6_string = hex::encode(self.k);
        // putting : after every 4th symbol
        for i in 1usize..8 {
            let pos = 4 * i + i - 1;
            ip6_string.insert(pos, ':');
        }
        f.write_str(&ip6_string)
    }
}

impl std::fmt::Debug for CJDNS_IP6 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        debug_fmt(self.k, f)
    }
}

impl CJDNS_IP6 {
    pub fn is_zero(&self) -> bool {
        self.k == [0; 16]
    }

    pub fn raw(&self) -> &[u8; Self::SIZE] {
        &self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv6_r(s: &'static str) -> Result<CJDNS_IP6> {
        CJDNS_IP6::try_from(s)
    }

    fn ipv6(s: &'static str) -> CJDNS_IP6 {
        ipv6_r(s).expect("bad test ipv6")
    }

    #[test]
    fn test_ip6_from_string() {
        // Valid cases
        assert!(ipv6_r("fc32:6a5d:e235:7057:e990:6398:5d7a:aa58").is_ok());

        // Invalid cases
        let invalid_ips = vec![
            // wrong len
            ipv6_r("fc32:6a5d7057:e990:6398:5d7a:aa58"),
            // wrong format
            ipv6_r("fc32:6a5de:235:7057:e990:6398:5d7a:aa58"),
            ipv6_r("fc326a5de2357057e99063985d7aaa58"),
            ipv6_r("ac32:6a5d:e235:7057:e990:6398:5d7a:aa58"),
            ipv6_r("FC32:6a5d:e235:7057:e990:6398:5D7a:Aa58"),
            ipv6_r("6a5d:fc32:e235:e990:7057:6398:5d7a:aa58"),
        ];
        for err_res in invalid_ips {
            assert!(err_res.is_err());
        }
    }

    #[test]
    fn to_from_bytes_ip6() {
        let ip6 = ipv6("fc32:6a5d:e235:7057:e990:6398:5d7a:aa58");
        let ip6_bytes = ip6.k;
        assert_eq!(&*ip6, &ip6_bytes);
        assert_eq!(CJDNS_IP6::try_from(ip6_bytes.as_ref()).expect("invalid ip6 bytes"), ip6);
        assert_eq!(ip6.to_string(), "fc32:6a5d:e235:7057:e990:6398:5d7a:aa58".to_string());

        // notice, that such key creation is impossible for library users
        let invalid_ip6_bytes = vec![
            hex::decode("e4c53a4aa8f29325b94a74c326fd40de").expect("invalid hex string"),
            hex::decode("7e413a71c767573f61277956b69ab700").expect("invalid hex string"),
        ];

        for i in invalid_ip6_bytes {
            assert!(CJDNS_IP6::try_from(i.as_slice()).is_err())
        }
    }

    #[test]
    fn test_zero_ip6() {
        let zeroes = [0_u8; 16];
        let zero = CJDNS_IP6::try_from(&zeroes[..]).expect("failed to construct zero IPv6");
        assert!(zero.is_zero());
        assert!(!ipv6("fc32:6a5d:e235:7057:e990:6398:5d7a:aa58").is_zero());
    }
}
