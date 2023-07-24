#[derive(Debug)]
pub struct DataReader(usize);
use crate::error::Result;
use crate::error::ErrorKind;

impl DataReader {
    pub fn new() -> DataReader {
        DataReader(0)
    }

    pub fn with_pos(pos:usize) -> DataReader {
        DataReader(pos)
    }

    fn advance_position(&mut self, max_len: usize, len: usize) -> Result<usize> {
        let o = self.0;
        if max_len < len + o {
            Err(ErrorKind::TooShort)
        } else {
            self.0+=len;
            Ok(o)
        }
    }

    pub fn get_u8(&mut self, data: &[u8]) -> Result<u8> {
        let o = self.advance_position(data.len(), 1)?;
        Ok(data[o])
    }

    pub fn get_bool(&mut self, data: &[u8]) -> Result<bool> {
        let o = self.advance_position(data.len(), 1)?;
        Ok(data[o] != 0)
    }

    pub fn get_u32(&mut self, data: &[u8]) -> Result<u32> {
        let o = self.advance_position(data.len(), 4)?;
        Ok(
            ((data[o] as u32) << 24) |
            ((data[o+1] as u32) << 16) |
            ((data[o+2] as u32) << 8) |
            (data[o+3] as u32)
        )
    }

    pub fn get_slice<'a>(&mut self, data:&'a [u8]) -> Result<&'a [u8]> {
        let len = self.get_u32(data)? as usize;
        let o = self.advance_position(data.len(), len)?;
        Ok(&data[o..o+len])
    }

}
