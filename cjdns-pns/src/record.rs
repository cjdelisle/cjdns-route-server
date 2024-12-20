use std::str::FromStr;

use cjdns_bytes::tlv::{encode_tlv, parse_tlv};
use eyre::{bail, Result};
use hickory_server::proto::{
    rr::{
        rdata::{A,AAAA, CNAME, NS, TXT},
        Record,
        Name,
        RecordData,
    },
    serialize::binary::{BinDecodable,BinEncodable},
};


pub const RECORD_TYPES: &'static [&'static str] = &[
    "A",
    "AAAA",
    // "CAA",
    "CNAME",
    "NS",
    // "SRV",
    "TXT",
];

struct JsonRecord {
    rtype: String,
    name: String,
    value: String,
    ttl_sec: u32,
}

pub fn parse_record_str(rtype: &str, name: &str, value: &str, ttl_sec: u32) -> Result<Record> {
    let name = Name::from_str(name)?;
    let out = match rtype {
        "A" => A::from_str(value)?.into_rdata(),
        "AAAA" => AAAA::from_str(value)?.into_rdata(),
        // "CAA" => CAA::from_str(s)?.into_rdata(),
        "CNAME" => CNAME(Name::parse(value, None)?).into_rdata(),
        "NS" => NS(Name::parse(value, None)?).into_rdata(),
        // "SRV" => SRV::
        "TXT" => TXT::from_bytes(vec![value.as_bytes()]).into_rdata(),
        other_type => {
            bail!("Unsupported record type {other_type}");
        }
    };
    Ok(Record::from_rdata(name, ttl_sec, out))
}

// We skip over 1,2,3,4 because they are used in the cjdns seeder reply which is also TLV.
// It's just a courtaesy to avoid confusion.
pub const RECORD: u8 = 0x05;

pub fn parse_records_bytes(bytes: &[u8]) -> Result<Vec<Record>> {
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