use crate::ssh_agent_types::*;

#[derive(Debug)]
pub struct MessageBuilder {
    msg: Vec<u8>,
}

impl MessageBuilder {

    pub fn new(id: u8) -> Self {
        let mut b = MessageBuilder {
            msg: Vec::with_capacity(64),
        };
        
        b.reset(id);
        b
    }

    pub fn reset(&mut self, id: u8) {
        self.msg.resize(5, 0);
        self.msg[4] = id;
    }

    pub fn build(&mut self) -> &[u8] {
        let length = (self.msg.len() - 4) as u32;
        self.msg[0] = ((length & 0xFF000000) >> 24) as u8;
        self.msg[1] = ((length & 0x00FF0000) >> 16) as u8;
        self.msg[2] = ((length & 0x0000FF00) >> 8) as u8;
        self.msg[3] = (length & 0x000000FF) as u8;
        self.msg.as_slice()
    }
    
    pub fn add_string(&mut self, part: String) -> &mut Self {
        return self.add_bytes(part);
    }

    pub fn add_u64(&mut self, part: u64) -> &mut Self {
        self.msg.reserve(8);
        self.msg.push(((part & 0xFF00000000000000) >> 56) as u8);
        self.msg.push(((part & 0x00FF000000000000) >> 48) as u8);
        self.msg.push(((part & 0x0000FF0000000000) >> 40) as u8);
        self.msg.push(((part & 0x000000FF00000000) >> 32) as u8);
        self.msg.push(((part & 0x00000000FF000000) >> 24) as u8);
        self.msg.push(((part & 0x0000000000FF0000) >> 16) as u8);
        self.msg.push(((part & 0x000000000000FF00) >> 8) as u8);
        self.msg.push((part & 0x00000000000000FF) as u8);
        self
    }

    pub fn add_u32(&mut self, part: u32) -> &mut Self {
        self.msg.reserve(4);
        Self::add_u32_to_vec(&mut self.msg, part);
        self
    }

    pub fn add_big_uint(&mut self, part: num_bigint::BigUint) -> &mut Self {
        self.add_bytes(part.to_bytes_be())
    }

    pub fn add_big_int(&mut self, part: num_bigint::BigInt) -> &mut Self {
        self.add_bytes(part.to_signed_bytes_be())
    }

    pub fn add_str(&mut self, part: &str) -> &mut Self {
        return self.add_bytes(part);
    }

    pub fn add_byte(&mut self, part: u8) -> &mut Self {
        self.msg.push(part);
        self
    }

    pub fn add_bool(&mut self, part: bool) -> &mut Self {
        self.msg.push( if part { 1 } else { 0 });
        self
    }

    fn add_u32_to_vec(vec:&mut Vec<u8>, num:u32) {
        vec.push(((num & 0xFF000000) >> 24) as u8);
        vec.push(((num & 0x00FF0000) >> 16) as u8);
        vec.push(((num & 0x0000FF00) >> 8) as u8);
        vec.push((num & 0x000000FF) as u8);
    }

    pub fn add_sub_message(&mut self, parts: &[&[u8]]) -> &mut Self {
        let len = parts.iter().map(|e| e.len() + 4).sum::<usize>();
        let mut data: Vec<u8> = Vec::with_capacity(len);
        for part in parts {
            Self::add_u32_to_vec(&mut data, part.len() as u32);
            data.extend_from_slice(part);
        }
        return self.add_bytes(data);
    }

    pub fn add_bytes<T: AsRef<[u8]>>(&mut self, part: T) -> &mut Self {
        let bytes = part.as_ref();
        let length = bytes.len() as u32;
        self.add_u32(length);
        self.msg.extend_from_slice(bytes);
        self
    }

    pub fn failure() ->  MessageBuilder {
        MessageBuilder::new(SshAgentResponseType::Failure as u8)
    }

    pub fn success() ->  MessageBuilder {
        MessageBuilder::new(SshAgentResponseType::Success as u8)
    }

}

