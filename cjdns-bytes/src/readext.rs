use crate::var_int::{read_var_int, VarInt, VarIntError};

pub trait ReadExt: std::io::Read + Sized {
    fn read_bytes<T: AsMut<[u8]>>(&mut self) -> std::io::Result<T> {
        let mut t: T = unsafe { std::mem::zeroed() };
        self.read_exact(t.as_mut())?;
        Ok(t)
    }
    fn read_var_int<T: VarInt>(&mut self) -> Result<T,VarIntError> {
        read_var_int(self)
    }
}
impl<X> ReadExt for X where X: std::io::Read {}