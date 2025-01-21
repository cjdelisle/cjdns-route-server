use std::str::FromStr;

use cjdns_bytes::tlv::{encode_tlv, parse_tlv};
use eyre::{bail, Context, OptionExt, Result};
use hickory_server::proto::{
    rr::{
        rdata::TXT,
        Name,
        RData,
        Record,
        RecordData,
        RecordType,
    },
    serialize::{
        binary::{BinDecodable,BinEncodable},
        txt::RDataParser,
    },
};
use serde::{Deserialize, Serialize};

pub const RECORD_TYPES: &'static [&'static str] = &[
    "A",
    "AAAA",
    // "CAA",
    "CNAME",
    "NS",
    // "SRV",
    "TXT",
    "MX",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRecord {
    pub rtype: String,
    pub name: String,
    pub value: String,
    pub ttl_sec: u32,
}
impl TryFrom<&JsonRecord> for Record {
    type Error = eyre::Error;
    fn try_from(jr: &JsonRecord) -> Result<Self> {
        parse_record_str(&jr.rtype, &jr.name, &jr.value, jr.ttl_sec)
    }
}
impl TryFrom<&Record> for JsonRecord {
    type Error = eyre::Error;
    fn try_from(r: &Record) -> Result<Self> {
        let name = r.name().to_string();
        let name = if name.is_empty() {
            "@".to_string()
        } else {
            name
        };
        Ok(JsonRecord {
            rtype: r.record_type().to_string(),
            name,
            value: r.data().ok_or_eyre("Record has no RData")?.to_string(),
            ttl_sec: r.ttl(),
        })
    }
}
fn parse_record_str(rtype: &str, name: &str, value: &str, ttl_sec: u32) -> Result<Record> {
    let name = if name == "@" {
        Name::from_str("").context("Unable to parse record name: @")?
    } else {
        Name::from_str(name).with_context(||format!("Unable to parse record name: {name}"))?
    };
    let out = match rtype {
        // If you don't manual encode the TXT record, spaces get stripped.
        "TXT" => TXT::from_bytes(vec![value.as_bytes()]).into_rdata(),
        other_type => {
            let rt = RecordType::from_str(other_type)?;
            // If the rtype is MX and they put just the mailserver without the number before
            // it, we should add the default number of 10.
            if rt == RecordType::MX && !value.contains(" ") {
                RData::try_from_str(rt, &format!("10 {}", value))?
            } else {
                RData::try_from_str(rt, value)?
            }
        }
    };
    Ok(Record::from_rdata(name, ttl_sec, out))
}

// We skip over 1,2,3,4 because they are used in the cjdns seeder reply which is also TLV.
// It's just a courtaesy to avoid confusion.
pub const RECORD: u8 = 0x05;

pub fn decode_records(bytes: &[u8]) -> Result<Vec<Record>> {
    let recs = parse_tlv(bytes)?;
    let mut out = Vec::new();
    for (t, elem) in recs {
        if t != RECORD {
            bail!("Invalid record type {t}");
        }
        out.push(Record::from_bytes(elem)?);
    }
    Ok(out)
}

pub fn encode_records(records: &[Record]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for rec in records {
        out.push((RECORD, rec.to_bytes()?));
    }
    Ok(encode_tlv(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_test(jr: &JsonRecord) {
        let rec: Record = jr.try_into().unwrap();
        let enc = encode_records(&[rec.clone()]).unwrap();
        println!("{rec:?}");
        let dec = decode_records(&enc).unwrap();
        assert_eq!(dec.len(), 1);
        assert_eq!(dec[0], rec);
        let jr2: JsonRecord = (&rec).try_into().unwrap();
        assert_eq!(jr, &jr2);
    }

    #[test]
    fn test_record_parse() {
        roundtrip_test(&JsonRecord {
            rtype: "A".to_string(),
            name: "example.com".to_string(),
            value: "1.2.3.4".to_string(),
            ttl_sec: 300,
        });
        roundtrip_test(&JsonRecord {
            rtype: "AAAA".to_string(),
            name: "abcd".to_string(),
            value: "2001:1:22:333::".to_string(),
            ttl_sec: 400,
        });
        roundtrip_test(&JsonRecord {
            rtype: "CNAME".to_string(),
            name: "helloworld".to_string(),
            value: "example.com".to_string(),
            ttl_sec: 400,
        });
        roundtrip_test(&JsonRecord {
            rtype: "NS".to_string(),
            name: "test".to_string(),
            value: "ns1.example.com".to_string(),
            ttl_sec: 400,
        });
        roundtrip_test(&JsonRecord {
            rtype: "TXT".to_string(),
            name: "txtrec".to_string(),
            value: "This is a text rec".to_string(),
            ttl_sec: 400,
        });
        roundtrip_test(&JsonRecord {
            rtype: "TXT".to_string(),
            name: "@".to_string(),
            value: "This is a text rec".to_string(),
            ttl_sec: 400,
        });
        roundtrip_test(&JsonRecord {
            rtype: "MX".to_string(),
            name: "mail".to_string(),
            value: "10 mail.example.com".to_string(),
            ttl_sec: 400,
        });
        roundtrip_test(&JsonRecord {
            rtype: "MX".to_string(),
            name: "mail".to_string(),
            value: "mail.example.com".to_string(),
            ttl_sec: 400,
        });
    }
}