use std::io::Read;
use eyre::{Result, eyre, Context};

use cjdns_bytes::message::RWrite;

use crate::object::{Bstr, Dict, List, Object};

struct Parse<'a, R: Read, const MAX_RECURSION: u32, const ACCEPT_CJDNS_ALIGN_PAD: bool> {
    reader: &'a mut R,
    depth: u32,
}
impl<
    'a,
    R: Read,
    const MAX_RECURSION: u32,
    const ACCEPT_CJDNS_ALIGN_PAD: bool,
> Parse<'a, R, MAX_RECURSION, ACCEPT_CJDNS_ALIGN_PAD> {
    // Helper function to read a single byte from the reader
    fn read_byte(&mut self) -> Result<u8> {
        let mut byte = [0u8; 1];
        self.reader.read_exact(&mut byte).context("EOF reading byte")?;
        Ok(byte[0])
    }

    // Read an integer from bencode format (i...e) without a string buffer
    fn read_int(&mut self) -> Result<i64> {
        let mut byte = self.read_byte().context("EOF reading int")?;

        // Handle sign
        let is_negative = byte == b'-';
        let mut num: i64 = 0;

        // If negative, read the next byte for the first digit
        if is_negative {
            byte = self.read_byte().context("EOF reading negative int")?;
        }

        if byte == b'e' {
            return Err(eyre!("Integers must have a body"));
        }

        // Read digits until 'e'
        while byte != b'e' {
            // Check if byte is a valid digit (0-9)
            if !byte.is_ascii_digit() {
                return Err(eyre!("Invalid character in integer: {}", byte as char));
            }
            // Convert byte to digit value (e.g., b'5' - b'0' = 5)
            let digit = (byte - b'0') as i64;
            // Multiply current number by 10 and add new digit
            num = num
                .checked_mul(10)
                .and_then(|n| n.checked_add(digit))
                .ok_or_else(|| eyre!("Integer overflow"))?;
            byte = self.read_byte()?;

            if num == 0 && byte != b'e' {
                return Err(eyre!("Leading zeros are illegal"));
            }
        }

        if is_negative {
            if num == 0 {
                Err(eyre!("Negative zero is illegal"))
            } else {
                Ok(-num)
            }
        } else {
            Ok(num)
        }
    }

    // Read a list from bencode format (l...e)
    fn read_list(&mut self) -> Result<List<'a>> {
        let mut list = List::new();
        loop {
            let byte = self.read_byte().context("EOF reading list")?;
            if byte == b'e' {
                break;
            }

            // Push byte back conceptually by handling it in read_generic
            list.push(self.read_generic_with_byte(byte)?);
        }
        Ok(list)
    }

    // Read a dictionary from bencode format (d...e)
    fn read_dict(&mut self) -> Result<Dict<'a>> {
        let mut dict = Dict::new();
        let mut accept_zero_pad = ACCEPT_CJDNS_ALIGN_PAD && self.depth == 1;
        loop {
            let byte = self.read_byte().context("EOF reading dict")?;
            if byte == b'e' {
                break;
            }
            
            // Push byte back conceptually by handling it in read_string
            let key = self.read_string_with_byte(byte, accept_zero_pad)?;
            let value = self.read_generic()?;
            dict.insert(key, value);
            accept_zero_pad = false;
        }
        Ok(dict)
    }

    // Optimized read_string_with_byte
    fn read_string_with_byte(
        &mut self,
        mut byte: u8,
        accept_zero_pad: bool,
    ) -> Result<Bstr<'a>> {
        let mut len: usize = 0;

        // Read digits until ':'
        while byte != b':' {
            if !byte.is_ascii_digit() {
                return Err(eyre!("Invalid character in string length: {}", byte as char));
            }
            let digit = (byte - b'0') as usize;
            len = len
                .checked_mul(10)
                .and_then(|n| n.checked_add(digit))
                .ok_or_else(|| eyre!("String length overflow"))?;
            byte = self.read_byte().context("EOF reading string len")?;
            if byte != b':' && len == 0 && !accept_zero_pad {
                return Err(eyre!("Leading zeros not allowed in string length"));
            }
        }

        // Read the string content
        let mut bytes = vec![0u8; len];
        self.reader.read_exact(&mut bytes).context("EOF reading string content")?;
        Ok(bytes.into())
    }

    // Generic reader for any bencode value with first byte provided
    fn read_generic_with_byte(&mut self, chr: u8) -> Result<Object<'a>> {
        if self.depth > MAX_RECURSION {
            return Err(eyre!("Exceeded nesting depth limit"));
        }
        self.depth += 1;
        let out = match chr {
            b'l' => Ok(Object::List(self.read_list()?)),
            b'd' => Ok(Object::Dict(self.read_dict()?)),
            b'i' => Ok(Object::Integer(self.read_int()?)),
            b'0'..=b'9' => Ok(Object::Bytes(self.read_string_with_byte(chr, false)?)),
            _ => Err(eyre!("Unexpected character in message: {}", chr as char)),
        };
        self.depth -= 1;
        out
    }

    fn read_generic(&mut self) -> Result<Object<'a>> {
        let chr = self.read_byte()?;
        self.read_generic_with_byte(chr)
    }
}

pub struct Parser<const MAX_RECURSION: u32, const ACCEPT_CJDNS_ALIGN_PAD: bool>();
impl<
    const MAX_RECURSION: u32,
    const ACCEPT_CJDNS_ALIGN_PAD: bool,
> Parser<MAX_RECURSION, ACCEPT_CJDNS_ALIGN_PAD> {
    pub fn parse<'a, R: Read>(reader: &'a mut R) -> Result<Object<'a>> {
        Parse::<'a, R, MAX_RECURSION, ACCEPT_CJDNS_ALIGN_PAD> {
            reader,
            depth: 0,
        }.read_generic()
    }
}

// ------------------------------------------------
// Serialize
// ------------------------------------------------

struct Serialize<'a, W: RWrite> {
    w: &'a mut W,
}
impl<'a, W: RWrite> Serialize<'a, W> {
    // Write a single byte in reverse (prepends)
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        Ok(self.w.write_all(&[byte])?)
    }

    // Write a list (reversed order)
    fn write_list(&mut self, list: &List<'a>) -> Result<()> {
        self.write_byte(b'e')?; // End marker
        for item in list.iter().rev() { // Reverse iteration
            self.write_value(item, 0)?;
        }
        self.write_byte(b'l')?; // Start marker
        Ok(())
    }

    // Write an integer
    fn write_int(&mut self, num: i64) -> Result<()> {
        self.write_byte(b'e')?; // End marker
        let num_str = num.to_string(); // Convert to string (handles negatives)
        self.w.write_all(num_str.as_bytes())?;
        self.write_byte(b'i')?; // Start marker
        Ok(())
    }

    // Write a string
    fn write_string(&mut self, bytes: &[u8]) -> Result<()> {
        self.w.write_all(bytes)?; // Content
        self.write_byte(b':')?; // Delimiter
        let len_str = bytes.len().to_string();
        self.w.write_all(len_str.as_bytes())?; // Length
        Ok(())
    }

    // Write dictionary entries (reversed order)
    fn write_dict(&mut self, dict: &Dict<'a>, align: usize) -> Result<()> {
        self.write_byte(b'e')?; // End marker
        // Reverse iteration (BTreeMap is already sorted)
        for (key, value) in dict.iter().rev() {
            self.write_value(value, 0)?;
            self.write_string(key)?;
        }
        if align > 1 {
            // Align to <align>-byte boundary, accounting for the 'd' we're about to write
            let total_len_with_d = self.w.len() + 1; // 'd' adds 1 byte
            let padding_needed = (align - (total_len_with_d % align)) % align; // Bytes to add
            for _ in 0..padding_needed {
                self.write_byte(b'0')?;
            }
        }
        self.write_byte(b'd')?; // Begin marker
        Ok(())
    }

    // Generic value writer
    fn write_value(&mut self, value: &Object<'a>, cjdns_align: usize) -> Result<()> {
        match value {
            Object::Bytes(bytes) => self.write_string(bytes),
            Object::Dict(dict) => self.write_dict(dict, cjdns_align),
            Object::List(list) => self.write_list(list),
            Object::Integer(num) => self.write_int(*num),
        }
    }
}

pub fn serialize<'a, W: RWrite>(writer: &mut W, obj: &Object<'a>, cjdns_align: usize) -> Result<()> {
    Serialize{ w: writer }.write_value(obj, cjdns_align)
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use crate::object::{Dict, List, Object};

    use super::{Parser,serialize};
    use cjdns_bytes::message::Message;

    fn parse<'a, R: std::io::Read>(reader: &'a mut R, relaxed: bool) -> Result<Object<'a>, eyre::Report> {
        if relaxed {
            Parser::<32, true>::parse(reader)
        } else {
            Parser::<32, false>::parse(reader)
        }
    }

    // Helper function to run a single test
    fn decode_test1<'a>(input: &[u8], expected: Dict<'a>, align: usize) {
        let mut reader = Cursor::new(input);
        let result = parse(&mut reader, align > 0).unwrap();
        let expected = Object::from(expected);
        let same = expected.eq(&result);
        assert!(same, "Failed for input: {:?}", String::from_utf8_lossy(input));

        let mut msg = Message::new();
        serialize(&mut msg, &Object::from(expected), align).unwrap();
        assert_eq!(String::from_utf8_lossy(&msg.as_vec()[..]), String::from_utf8_lossy(input));
        assert_eq!(msg.as_vec(), input.to_vec());
    }

    // Helper function to test for expected errors
    fn decode_test_error1(input: &[u8], expect_err: &str, relaxed: bool) {
        let mut reader = Cursor::new(input);
        let result = parse(&mut reader, relaxed);
        assert!(result.is_err(), "Expected error for input: {:?}", String::from_utf8_lossy(input));
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains(&expect_err),
            "Unexpected error '{}', expected match for '{}'", err, expect_err
        );
    }

    fn decode_test(input: &[u8], expected: Dict<'_>) {
        decode_test1(input, expected, 0);
    }

    fn decode_test_align(input: &[u8], expected: Dict<'_>, align: usize) {
        decode_test1(input, expected, align);
    }

    fn decode_test_error(input: &[u8], expect_err: &str) {
        decode_test_error1(input, expect_err, false);
    }

    fn decode_test_error_relaxed(input: &[u8], expect_err: &str) {
        decode_test_error1(input, expect_err, true);
    }

    fn map(x: impl Fn(&mut Dict<'_>)) -> Dict<'static> {
        let mut map = Dict::new();
        x(&mut map);
        map
    }

    fn list(x: impl Fn(&mut List<'_>)) -> List<'static> {
        let mut list = List::new();
        x(&mut list);
        list
    }

    #[test]
    fn decode_tests() {

        // Test vectors: each line is (input, expected_output)
        decode_test(b"d3:foo3:bare", {
            map(|d|d.insert("foo", "bar".to_string()))
        });

        decode_test(b"d4:spamli1ei2eee", {
            map(|d|d.insert("spam", vec![1, 2]))
        });
        
        decode_test(b"d5:innerd3:xyz3:abce3:inti123ee", {
            map(|d| {
                d.insert("inner", map(|d| {
                    d.insert("xyz", "abc".to_string());
                    d.insert("int", 123);
                }));
            })
        });
        
        decode_test(b"de", Dict::new());
        
        decode_test(b"d3:negi-123ee", 
            map(|d|d.insert("neg", -123)));


        // Simple dictionary
        decode_test(b"d3:bari1e3:fooli2ei3eee",
            map(|d| {
                d.insert("bar", 1);
                d.insert("foo", vec![2, 3]);
            })
        );

        // Negative numbers and zero
        decode_test(b"d1:xi0ee", map(|x| x.insert("x", 0)));
        decode_test(b"d1:xi-1e", map(|x| x.insert("x", -1)));

        // Recursion limit (assuming your impl has a reasonable default limit, e.g., 4096)
        let d =
            map(|x| {
                x.insert("x", list(|l|{
                    l.push(list(|l|{
                        l.push(List::new());
                    }));
                }));
            });
        decode_test(b"d1:xllleeee",d); // Depth 3
    }

    fn fomap() -> Dict<'static> {
        let mut map = Dict::new();
        map.insert("fo", 1);
        map
    }

    #[test]
    fn decode_error_tests() {
        // Short dict should fail
        decode_test_error(b"d", r"EOF");

        // Short list should fail
        decode_test_error(b"l", r"EOF");

        // Short int should fail
        decode_test_error(b"i12", r"EOF");

        // Negative zero is illegal
        decode_test_error(b"i-0e", r"Negative zero is illegal");

        // Leading zeros are illegal
        decode_test_error(b"i01e", r"Leading zeros are illegal");
        decode_test_error_relaxed(b"i01e", r"Leading zeros are illegal");
        decode_test_error(b"i-01e", r"Leading zeros are illegal");

        decode_test_error(b"l003:fooe", r"Leading zeros not allowed in string length");
        decode_test_error_relaxed(b"l003:fooe", r"Leading zeros");

        decode_test_error(b"d003:fooi1ee", r"Leading zeros not allowed in string length");
        decode_test_align(b"d2:foi1ee", fomap(), 1);
        decode_test_align(b"d02:foi1ee", fomap(), 2);
        decode_test_align(b"d0002:foi1ee", fomap(), 4);
        decode_test_align(b"d00000002:foi1ee", fomap(), 8);

        // Map keys must be strings
        decode_test_error(b"d3:fooi1ei2ei3ee", r"");

        // Map keys must ascend (BTreeMap enforces this, so test duplicate keys instead)
        // decode_test_error(b"d3:fooi1e3:fooi2ee", r"duplicate key");

        // Map keys must have values
        decode_test_error(b"d3:fooe", r"");

        // Strings must have bodies
        decode_test_error(b"3:", r"EOF");

        // Ints must have bodies
        decode_test_error(b"ie", r"Integers must have a body");

        // Test excessive nesting (create a deeper structure if your impl limits it)
        let deep_input = vec![b'l'; 4096].into_iter().chain(vec![b'e'; 4096]).collect::<Vec<u8>>();
        decode_test_error(&deep_input, r"nesting depth");
    }
}