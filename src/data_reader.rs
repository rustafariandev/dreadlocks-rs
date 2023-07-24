use crate::error::Result;
use crate::error::ErrorKind;

#[derive(Debug)]
pub struct DataReader <'a> {
    pos: usize,
    data: &'a [u8],
}

impl<'a> DataReader<'a> {
    pub fn new(data: &[u8]) -> DataReader {
        DataReader{pos: 0,data}
    }

    pub fn with_pos(pos:usize, data: &[u8]) -> DataReader {
        DataReader{pos, data}
    }

    fn advance_position(&mut self, max_len: usize, len: usize) -> Result<usize> {
        let o = self.pos;
        if max_len < len + o {
            Err(ErrorKind::TooShort)
        } else {
            self.pos+=len;
            Ok(o)
        }
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        let o = self.advance_position(self.data.len(), 1)?;
        Ok(self.data[o])
    }

    pub fn get_bool(&mut self) -> Result<bool> {
        let o = self.advance_position(self.data.len(), 1)?;
        Ok(self.data[o] != 0)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        let o = self.advance_position(self.data.len(), 4)?;
        Ok(
            ((self.data[o] as u32) << 24) |
            ((self.data[o+1] as u32) << 16) |
            ((self.data[o+2] as u32) << 8) |
            (self.data[o+3] as u32)
        )
    }

    pub fn get_slice(&mut self) -> Result<&'a [u8]> {
        let len = self.get_u32()? as usize;
        let o = self.advance_position(self.data.len(), len)?;
        Ok(&self.data[o..o+len])
    }

}
