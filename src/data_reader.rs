use crate::error::ErrorKind;
use crate::error::Result;

#[derive(Debug)]
pub struct DataReader<'a> {
    pos: usize,
    data: &'a [u8],
}

pub trait TryFromDataReader {
    fn try_from_data_reader(r: &mut DataReader<'_>) -> Result<Self>
    where
        Self: Sized;
}

impl<'a> DataReader<'a> {
    pub fn new(data: &[u8]) -> DataReader {
        DataReader { pos: 0, data }
    }

    pub fn with_pos(pos: usize, data: &[u8]) -> DataReader {
        DataReader { pos, data }
    }

    fn check_space(&self, len: usize) -> Result<()> {
        if self.data.len() < len + self.pos {
            return Err(ErrorKind::TooShort);
        }

        Ok(())
    }

    fn advance_position(&mut self, len: usize) -> Result<usize> {
        self.check_space(len)?;
        let o = self.pos;
        self.pos += len;
        Ok(o)
    }

    pub fn skip_u8(&mut self) -> Result<()> {
        self.advance_position(1)?;
        Ok(())
    }

    pub fn peek_u32(&mut self) -> Result<u32> {
        self.check_space(4)?;
        let o = self.pos;
        Ok(Self::extract_u32(self.data, o))
    }

    fn extract_u32(data: &[u8], o: usize) -> u32 {
        ((data[o] as u32) << 24)
            | ((data[o + 1] as u32) << 16)
            | ((data[o + 2] as u32) << 8)
            | (data[o + 3] as u32)
    }

    pub fn skip_slice(&mut self) -> Result<()> {
        let len = self.peek_u32()? as usize;
        self.advance_position(len + 4)?;
        Ok(())
    }

    pub fn peek_slice(&mut self) -> Result<&'a [u8]> {
        let len = self.peek_u32()? as usize;
        self.check_space(len + 4)?;
        let o = self.pos + 4;
        Ok(&self.data[o..o + len])
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        let o = self.advance_position(1)?;
        Ok(self.data[o])
    }

    pub fn get_bool(&mut self) -> Result<bool> {
        let o = self.advance_position(1)?;
        Ok(self.data[o] != 0)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        let o = self.advance_position(4)?;
        Ok(Self::extract_u32(self.data, o))
    }

    pub fn get_slice(&mut self) -> Result<&'a [u8]> {
        let len = self.get_u32()? as usize;
        let o = self.advance_position(len)?;
        Ok(&self.data[o..o + len])
    }

    pub fn more(&self) -> bool {
        self.data.len() < self.pos
    }
}
