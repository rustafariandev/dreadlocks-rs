#[derive(Debug)]
pub struct DataReader(usize);

impl DataReader {
    pub fn new() -> DataReader {
        DataReader(0)
    }

    pub fn with_pos(pos:usize) -> DataReader {
        DataReader(pos)
    }

    fn advance_position(&mut self, max_len: usize, len: usize) -> Option<usize> {
        let o = self.0;
        if max_len < len + o {
            None
        } else {
            self.0+=len;
            Some(o)
        }
    }

    pub fn get_u8(&mut self, data: &[u8]) -> Option<u8> {
        let o = self.advance_position(data.len(), 1)?;
        Some(data[o])
    }

    pub fn get_bool(&mut self, data: &[u8]) -> Option<bool> {
        let o = self.advance_position(data.len(), 1)?;
        Some(data[o] != 0)
    }

    pub fn get_u32(&mut self, data: &[u8]) -> Option<u32> {
        let o = self.advance_position(data.len(), 4)?;
        Some(
            ((data[o] as u32) << 24) |
            ((data[o+1] as u32) << 16) |
            ((data[o+2] as u32) << 8) |
            (data[o+3] as u32)
        )
    }

    pub fn get_slice<'a>(&mut self, data:&'a [u8]) -> Option<&'a [u8]> {
        let len = self.get_u32(data)? as usize;
        let o = self.advance_position(data.len(), len)?;
        Some(&data[o..o+len])
    }

}
