//! Node name parsing utilities

use std::convert::TryFrom;

use eyre::{eyre, Result, OptionExt, Context};
use regex::Regex;

use cjdns_keys::CJDNSPublicKey;

use crate::RoutingLabel;

pub struct Address {
    pub version: u16,
    pub label: RoutingLabel<u64>,
    pub pubkey: CJDNSPublicKey,
}

lazy_static! {
    static ref NODE_NAME_RE: Regex = Regex::new(
        "^v([0-9]+)\\.\
        ([[:xdigit:]]{4}\\.[[:xdigit:]]{4}\\.[[:xdigit:]]{4}\\.[[:xdigit:]]{4})\\.\
        ([a-z0-9]{52}\\.k)"
    )
    .expect("bad regexp");
}

impl ToString for Address {
    fn to_string(&self) -> String {
        format!("v{}.{}.{}", self.version, self.label, self.pubkey)
    }
}

/// Gets version, label and public key all together in tuple from `name` argument, if it has valid structure.
/// Otherwise returns error.
impl TryFrom<&str> for Address {
    type Error = eyre::Error;

    fn try_from(name: &str) -> eyre::Result<Self> {
        if let Some(c) = NODE_NAME_RE.captures(name) {
            let str_from_captured_group = |group_num: usize| -> Result<&str> {
                Ok(c.get(group_num).ok_or_eyre("bad group index")?.as_str())
            };
            let version = str_from_captured_group(1)?.parse::<u16>()
                .context("Version does not parse")?;
            let label = RoutingLabel::try_from(str_from_captured_group(2)?)
                .context("Label does not parse")?;
            let pubkey = CJDNSPublicKey::try_from(str_from_captured_group(3)?)
                .context("Key does not parse")?;
            Ok(Address{ version, label, pubkey })
        } else {
            Err(eyre!("Address: {name} does not match regex"))
        }
    }
}

#[test]
fn test_parse_node_name_valid() {
    let valid_node_names = vec![
        "v19.0000.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
        "v10.0a20.00ff.00e0.9901.qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k",
    ];
    for valid_node_name in valid_node_names {
        assert!(Address::try_from(valid_node_name).is_ok());
    }
}

#[test]
fn test_parse_node_name_invalid() {
    let invalid_node_names = vec![
        "12foo",
        "",
        "19.0000.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
        "v1234123123.0000.00000.000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
        "v19.0000.0000.0000.0863.2v6dt6f841hZhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
        "v19.0ffe.1200.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtpy50.k",
        "v19.gh00.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
        "v10.0000.0000.0000.0001.aer2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k",
        "v10.0a20.00ff.00e0.9901.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.k)",
    ];
    for invalid_node_name in invalid_node_names {
        assert!(Address::try_from(invalid_node_name).is_err());
    }
}
