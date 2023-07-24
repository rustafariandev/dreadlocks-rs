
use num_enum::TryFromPrimitive;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug)]
pub struct MessageBuilder {
    msg: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum SshAgentRequestType {
    RsaIdentities = 1,
    RsaChallenge = 3,
    AddRsaIdentity = 7,
    RemoveRsaIdentity = 8,
    RemoveAllRsaIdentities = 9,

    RequestIdentities = 11,
    SignRequest = 13,
    AddIdentity = 17,
    RemoveIdentity =18,
    RemoveAllIdentities = 19,

    /* smartcard */
    AddSmartcardKey = 20,
    RemoveSmartcardKey = 21,

    /* LOCK/UNLOCK THE AGENT */
    Lock = 22,
    Unlock = 23,

    AddRsaIdConstrained = 24,
    AddIdConstrained = 25,
    AddSmartcardKeyConstrained = 26,

    /* GENERIC EXTENSION MECHANISM */
    Extension = 27,
}

#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum SshAgentResponseType {
    /* Legacy */
    RsaIdentitiesAnswer = 2,
    RsaResponse = 4,

    /* Messages for the authentication agent connection. */
    Failure = 5,
    Success = 6,

    /* private OpenSSH extensions for SSH2 */
    IdentitiesAnswer = 12,
    SignResponse = 14,

    /* GENERIC EXTENSION MECHANISM */
    ExtensionFailure = 28,

}

impl MessageBuilder {

    pub fn new(id: u8) -> Self {
        let mut b = MessageBuilder{
            msg: Vec::new(),
        };
        
        b.msg.reserve(64);
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
        self.msg.push(((part & 0xFF000000) >> 24) as u8);
        self.msg.push(((part & 0x00FF0000) >> 16) as u8);
        self.msg.push(((part & 0x0000FF00) >> 8) as u8);
        self.msg.push((part & 0x000000FF) as u8);
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
        self.msg.push(
            if part { 1 } else { 0 }
        );
        self
    }

    fn add_bytes<T: AsRef<[u8]>>(&mut self, part: T) -> &mut Self {
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

#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct MessageReader {
    data:Vec<u8>,
    position: usize,
}

impl<'a: 'b, 'b> MessageReader {
    pub fn new(data:Vec<u8>) -> Option<MessageReader> {
        if data.len() >= 5 {
            Some(
                MessageReader{
                    data,
                    position:5
                }
            )
        } else {
            None
        }
    }

    pub fn current_position(&self) -> usize {
        self.position
    }

    pub fn get_type(&self) -> u8 {
        self.data[4]
    }
    
    fn more(&self) -> bool {
        self.position < self.data.len() 
    }

    pub fn check_pos(&self, pos: usize, len: usize) -> Option<()> {
        if self.data.len() < pos + len  {
            return None;
        }

        Some(())
    }

    fn advance_position(&mut self, len: usize) -> Option<usize> {
        let o = self.position;
        if self.data.len() - o < len  {
            None
        } else {
            self.position+=len;
            Some(o)
        }
    }

    pub fn get_u8(&mut self) -> Option<u8> {
        let o = self.advance_position(1)?;
        Some(self.data[o])
    }

    pub fn get_u8_at(&self, pos: usize) -> Option<(u8, usize)> {
        self.check_pos(pos, 1)?;
        Some((self.data[pos], pos + 1))
    }

    pub fn get_bool(&mut self) -> Option<bool> {
        let o = self.advance_position(1)?;
        Some(if self.data[o] == 0 { false } else { true })
    }

    pub fn get_bool_at(&self, pos: usize) -> Option<(bool, usize)> {
        self.check_pos(pos, 1)?;
        Some(
            (
                if self.data[pos] == 0 { false } else { true },
                pos + 1
            )
        )
    }

    pub fn get_u32(&mut self) -> Option<u32> {
        let o = self.advance_position(4)?;
        Some(
            ((self.data[o] as u32) << 24) |
            ((self.data[o+1] as u32) << 16) |
            ((self.data[o+2] as u32) << 8) |
            ((self.data[o+3] as u32) )
        )
    }

    pub fn get_u32_at(&self, o: usize) -> Option<(u32, usize)> {
        self.check_pos(o, 4)?;
        Some(
            (
            ((self.data[o] as u32) << 24) |
            ((self.data[o+1] as u32) << 16) |
            ((self.data[o+2] as u32) << 8) |
            ((self.data[o+3] as u32) ),
            o+4
            )
        )
    }

    pub fn get_slice(&'a mut self) -> Option<&'b [u8]> {
        let len = self.get_u32()? as usize;
        let o = self.advance_position(len)?;
        Some(&self.data[o..o+len])
    }

    pub fn get_slice_at(&'a self, o: usize) -> Option<(&'b [u8], usize)> {
        self.check_pos(o, 4)?;
        let (len, o) = self.get_u32_at(o)?;
        let len = len as usize;
        Some((&self.data[o..o+len], o+len))
    }

    pub fn set_position(&mut self, o: usize) {
        self.position = o;
    }
}
