use std::ops::Deref;

use eyre::{bail, Result};

// NOTE: This TLV implementation includes the length of the type field and length field.

pub fn parse_tlv(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut cursor = 0;
    let mut out = Vec::new();
    // println!("Begin parse TLV");
    while cursor + 1 < bytes.len() {
        let t = bytes[cursor];
        let l = bytes[cursor + 1] as usize;
        // println!("TLV({t},{l}) cursor={cursor} len() = {}", bytes.len());
        if l < 2 {
            bail!("Invalid item length: {l}");
        } else if l + cursor > bytes.len() {
            bail!("TLV is truncated");
        }
        out.push((t, &bytes[cursor + 2 .. cursor + l]));
        cursor += l;
    }
    Ok(out)
}

pub fn encode_tlv<V>(items: &[(u8, V)]) -> Vec<u8>
    where V: Deref<Target = [u8]>
{
    let mut out = Vec::new();
    for (t, v) in items {
        let v: &[u8] = &*v;
        out.push(*t);
        out.push(v.len() as u8 + 2);
        out.extend_from_slice(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_tlv() -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..rng.gen_range(0,10) {
            let t: u8 = rng.gen();
            let l = rng.gen_range(0,10);
            let mut v = Vec::new();
            for _ in 0..l {
                v.push(rng.gen());
            }
            out.push((t, v));
        }
        out
    }

    #[test]
    fn test_parse_tlv() {
        for _ in 0..100 {
            let tlv = random_tlv();
            // println!("TLV: {tlv:?}");
            let enc = encode_tlv(&tlv);
            // println!("TLV ENCODED: {enc:?}");
            let dec = parse_tlv(&enc).unwrap();
            let _ =  encode_tlv(&dec); // Just to check that it compiles like this
            let dec: Vec<(u8, Vec<u8>)> = dec.into_iter().map(|(t, v)| (t, v.to_vec())).collect();
            assert_eq!(tlv, dec);
        }
    }
}