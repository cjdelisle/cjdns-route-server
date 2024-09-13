use std::io::{Read, Write};

#[derive(Debug)]
struct Overflow;

struct Chunk {
    bytes: Vec<u8>,
    offset: usize,
}
impl Chunk {
    fn new(size: usize) -> Self {
        assert!(size > 0);
        let bytes = vec![0;size]; // TODO(cjd): Slow
        Self {
            bytes,
            offset: size,
        }
    }
    #[inline]
    fn len(&self) -> usize {
        self.bytes.len() - self.offset
    }
    #[inline]
    fn cap(&self) -> usize {
        self.offset
    }
    #[inline]
    fn pop(&mut self, out: &mut [u8]) -> Result<usize, Overflow> {
        if out.len() > self.len() {
            Err(Overflow)
        } else {
            out.copy_from_slice(&self.bytes[self.offset..self.offset + out.len()]);
            self.offset += out.len();
            Ok(out.len())
        }
    }
    #[inline]
    fn push(&mut self, input: &[u8]) -> Result<usize, Overflow> {
        if input.len() > self.cap() {
            Err(Overflow)
        } else {
            let o0 = self.offset;
            self.offset -= input.len();
            self.bytes[self.offset..o0].copy_from_slice(input);
            Ok(input.len())
        }
    }
}

#[derive(Default)]
pub struct Message{
    chunk_sz: usize,
    chunks: Vec<Chunk>,
    spare_chunks: Vec<Chunk>
}

impl Message {
    const DEFAULT_CHUNK_SZ: usize = 4096;

    pub fn chunk_sz(&self) -> usize {
        if self.chunk_sz > 0 {
            self.chunk_sz
        } else {
            Self::DEFAULT_CHUNK_SZ
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_chunk_size(chunk_sz: usize) -> Self {
        Self {
            chunk_sz,
            ..Default::default()
        }
    }

    pub fn as_vec(&self) -> Vec<u8> {
        let mut vec1 = Vec::with_capacity(self.len());
        for s in self.iovec() {
            vec1.extend_from_slice(s);
        }
        vec1
    }

    // Read as an iovec
    pub fn iovec(&self) -> impl Iterator<Item=&[u8]> {
        self.chunks.iter().rev().map(|chk|&chk.bytes[chk.offset..])
    }

    fn take_writable_chunk(&mut self) -> Chunk {
        if let Some(chunk) = self.chunks.pop() {
            if chunk.cap() > 0 {
                return chunk;
            } else {
                self.chunks.push(chunk)
            }
        }
        if let Some(chunk) = self.spare_chunks.pop() {
            assert_eq!(chunk.cap(), chunk.bytes.len());
            chunk
        } else {
            Chunk::new(self.chunk_sz())
        }
    }
}

impl Read for Message {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes = 0;
        while let Some(mut chk) = self.chunks.pop() {
            if buf.len() >= chk.len() {
                let l = chk.len();
                let b = &mut buf[0..l];
                bytes += chk.pop(b).unwrap();
                assert!(chk.len() == 0);
                self.spare_chunks.push(chk);
                buf = &mut buf[l..];
            } else {
                bytes += chk.pop(buf).unwrap();
                assert!(chk.len() > 0);
                self.chunks.push(chk);
                return Ok(bytes);
            }
        }
        Ok(bytes)
    }

}

pub trait RWrite: Write {
    fn len(&self) -> usize;
}

impl Write for Message {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes = 0;
        while !buf.is_empty() {
            let mut chunk = self.take_writable_chunk();
            if buf.len() >= chunk.cap() {
                let l = chunk.cap();
                let b = &buf[buf.len()-l..buf.len()];
                bytes += chunk.push(b).unwrap();
                buf = &buf[0..buf.len()-l];
            } else {
                bytes += chunk.push(buf).unwrap();
                buf = &buf[0..0];
            }
            self.chunks.push(chunk);
        }
        Ok(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl RWrite for Message {
    fn len(&self) -> usize {
        self.chunks.iter().map(|c|c.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{ReadBytesExt, WriteBytesExt, BE};
    use rand::Rng;
    use std::collections::VecDeque;
    use std::io::{Read, Write};

    use crate::message::{Message, RWrite};

    fn test_underflow0(chunk_sz: usize) {
        let mut message = Message::with_chunk_size(chunk_sz);
        assert_eq!(message.len(), 0);
        assert!(message.write_u16::<BE>(0x0102).is_ok());
        assert_eq!(message.len(), 2);
        assert!(message.read_u32::<BE>().is_err());
        assert_eq!(message.len(), 0);
        assert!(message.write_u16::<BE>(0x0102).is_ok());
        assert_eq!(message.len(), 2);

        let mut x = [0_u8;4];
        let r = message.read(&mut x);
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), 2);
        assert_eq!(message.len(), 0);
        assert!(message.read(&mut x).unwrap() == 0);
    }
    #[test]
    fn test_underflow() {
        test_underflow0(1);
        test_underflow0(2);
        test_underflow0(8);
    }

    #[test]
    fn test_message() {
        // Step 1: Generate a dataset of random size between 1 and 1024 bytes
        let mut rng = rand::thread_rng();
        let dataset_size = rng.gen_range(1, 1024);
        let dataset: Vec<u8> = (0..dataset_size).map(|_| rng.gen()).collect();
    
        // Step 2: Select a random chunk size between 10% and 110% of the dataset size
        let chunk_size = rng.gen_range(
            (dataset_size as f64 * 0.1) as usize,
            (dataset_size as f64 * 1.1) as usize,
        );
        // println!("chunk_size = {}", chunk_size);
    
        // Step 3: Create a VecDeque<u8> with the dataset
        let mut deque: VecDeque<u8> = VecDeque::from(dataset.clone());

        // println!("{}", hex::encode(&dataset));
    
        // Step 4: Call the Message::with_chunk_size() constructor
        let mut message = Message::with_chunk_size(chunk_size);

        // Step 5: Perform 200 randomly selected reads and writes of random sizes
        for _ in 0..200 {
            assert_eq!(
                hex::encode(Vec::from(deque.clone())),
                hex::encode(&dataset[dataset.len()-deque.len()..]),
            );

            let mut vec1 = message.as_vec();
            vec1.reverse();
            assert_eq!(
                hex::encode(&dataset[0..vec1.len()]),
                hex::encode(&vec1),
            );

            // println!("\nCYCLE\n");

            let msg_len = dataset.len() - deque.len();
            assert_eq!(msg_len, message.len());
            let is_read = if deque.is_empty() {
                assert!(msg_len > 0);
                true
            } else if msg_len < 1 {
                assert!(!deque.is_empty());
                false
            } else {
                rng.gen()
            };
            if is_read {  // Perform a read
                let read_size = rng.gen_range(1,msg_len+1); // Random size for read
                let mut buffer = vec![0u8; read_size];
                // println!("[{} -> {}] read({}) {} -> {}", deque.len(), deque.len() + buffer.len(), buffer.len(), message.len(), message.len() - buffer.len());
                message.read_exact(&mut buffer).unwrap();
                // println!("Read => {}", hex::encode(&buffer));
                for b in buffer.into_iter() {
                    deque.push_front(b);
                }
                // println!("msglen = {}", message.len());
            } else {  // Perform a write
                let write_size = rng.gen_range(1, deque.len()+1); // Random size for write
                // println!("[{} -> {}] write({}) {} -> {}", deque.len(), deque.len() - write_size, write_size, message.len(), message.len() + write_size);
                let mut buffer = Vec::with_capacity(write_size);
                for _ in 0..write_size {
                    buffer.push(deque.pop_front().unwrap());
                }
                buffer.reverse();
                assert_eq!(write_size, buffer.len());
                message.write_all(&buffer).unwrap();
                // println!("msglen = {}", message.len());
            }
        }
    
        // Step 6: Pull all bytes out of the Message and return them to the VecDeque
        while dataset.len() > deque.len() {
            let msg_len = dataset.len() - deque.len();
            assert_eq!(msg_len, message.len());
            let mut buffer = vec![0u8; msg_len];
            message.read_exact(&mut buffer).unwrap();
            for b in buffer.into_iter() {
                deque.push_front(b);
            }
        }
    
        // Step 7: Check that the bytes in the VecDeque are the same as at the beginning
        assert_eq!(Vec::from(deque), dataset);
    }

    // #[test]
    // fn test_message_1000() {
    //     for _ in 0..1000 {
    //         test_message();
    //     }
    // }
}