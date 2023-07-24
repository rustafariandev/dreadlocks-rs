use crate::message_builder::*;
use crate::ssh_agent_types::*;
use crate::data_reader::*;
use crate::error::*;
use crate::ecdsa_key::EcDsaKey;

use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SafeBytes(pub Vec<u8>);

enum LockStatus {
	Locked,
	Unlocked,
}

pub struct SshAgent {
	lock_status: LockStatus,
    secret: SafeBytes,
    identities: Vec<SshIdentity>,
}

pub trait SshSigningKey {
    fn sign(&self, id:&SshIdentity, data: &[u8], _flags: u32) -> Result<Vec<u8>>;
    fn public_key(&self) -> Result<Vec<u8>>;
    fn matches(&self, key: &[u8]) -> bool {
        let mut reader = DataReader::new();
        let _key_type = match reader.get_slice(key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let given_public = match reader.get_slice(key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let public = match self.public_key() {
            Ok(v) => v,
            Err(_) => return false,
        };

        given_public == public
    }
}

pub struct Ed25519Key (ed25519_dalek::Keypair);

impl SshSigningKey for Ed25519Key {
    fn sign(&self, _: &SshIdentity, data: &[u8], _: u32) -> Result<Vec<u8>> {
        use ed25519_dalek::{Signer};
        Ok(
            append_parts(&[
                "ssh-ed25519".as_bytes(),
                self.0.sign(data).as_ref(),
            ])
        )
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.0.public.as_bytes().to_vec())
    }
}

pub enum SshKey {
    Ed25519Key(Ed25519Key),
    EcDsaNistP256(EcDsaKey<p256::NistP256>),
    EcDsaNistP384(EcDsaKey<p384::NistP384>),
}

pub struct SshIdentity {
    key_type: Vec<u8>,
    comment: Vec<u8>,
    key: SshKey,
}

pub fn add_u32_to_vec(vec:&mut Vec<u8>, num:u32) {
    vec.push(((num & 0xFF000000) >> 24) as u8);
    vec.push(((num & 0x00FF0000) >> 16) as u8);
    vec.push(((num & 0x0000FF00) >> 8) as u8);
    vec.push((num & 0x000000FF) as u8);
}

pub fn append_parts(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|e| e.len() + 4).sum::<usize>();
    let mut data: Vec<u8> = Vec::with_capacity(len);
    for part in parts {
        add_u32_to_vec(&mut data, part.len() as u32);
        data.extend_from_slice(part);
    }
    data
}

impl SshIdentity {
    pub fn from_bytes(data:&[u8]) -> Result<SshIdentity> {
        let mut reader = DataReader::with_pos(1);
        let key_type = reader.get_slice(data)?;
        let key_type_str = std::str::from_utf8(key_type)?;
        match key_type_str {
            "ssh-ed25519" => {
                let public = reader.get_slice(data)?;
                let private = reader.get_slice(data)?;
                let comment = reader.get_slice(data)?;
                Ok(SshIdentity{
                    key_type: append_parts(&[key_type, public]),
                    key: SshKey::Ed25519Key(
                        Ed25519Key(
                            ed25519_dalek::Keypair::from_bytes(private).map_err(|_| ErrorKind::KeyNotCreated)?
                        )
                    ),
                    comment: comment.to_vec(),
                })
            },
            "ecdsa-sha2-nistp256" => {
                let curve_name = reader.get_slice(&data)?;
                let q = reader.get_slice(&data)?;
                let d = reader.get_slice(&data)?;
                let private = if d[0] == 0 { &d[1..] } else {d };
                let comment = reader.get_slice(data)?;
                Ok(SshIdentity{
                    key_type: append_parts(&[key_type, curve_name, q]),
                    key: SshKey::EcDsaNistP256(
                        EcDsaKey::new(
                           p256::ecdsa::SigningKey::from_slice(private).map_err(|_| ErrorKind::KeyNotCreated)?,
                           key_type.to_vec(),
                           curve_name.to_vec(),
                        ),
                    ),
                    comment: comment.to_vec(),
                })
            },
            "ecdsa-sha2-nistp384" => {
                let curve_name = reader.get_slice(&data)?;
                let q = reader.get_slice(&data)?;
                let d = reader.get_slice(&data)?;
                let private = if d[0] == 0 { &d[1..] } else {d };
                let comment = reader.get_slice(data)?;
                Ok(SshIdentity{
                    key_type: append_parts(&[key_type, curve_name, q]),
                    key: SshKey::EcDsaNistP384(
                        EcDsaKey::new(
                           p384::ecdsa::SigningKey::from_slice(private).map_err(|_| ErrorKind::KeyNotCreated)?,
                           key_type.to_vec(),
                            curve_name.to_vec(),
                        ),
                    ),
                    comment: comment.to_vec(),
                })
            },
            _ => Err(ErrorKind::TypeNotFound),
        }
    }

    fn sign(&self, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        match &self.key {
            SshKey::Ed25519Key(key) => key.sign(self, data, _flags),
            SshKey::EcDsaNistP256(key) => key.sign(self, data, _flags),
            SshKey::EcDsaNistP384(key) => key.sign(self, data, _flags),
        }
    }

    fn matches(&self, blob: &[u8]) -> bool {
        match &self.key {
            SshKey::Ed25519Key(key) => key.matches(blob),
            SshKey::EcDsaNistP256(key) => key.matches(blob),
            SshKey::EcDsaNistP384(key) => key.matches(blob),
        }
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        match &self.key {
            SshKey::Ed25519Key(key) => key.public_key(),
            SshKey::EcDsaNistP256(key) => key.public_key(),
            SshKey::EcDsaNistP384(key) => key.public_key(),

        }
    }
}

impl SshAgent {
    pub fn new() -> SshAgent {
        SshAgent {
            lock_status: LockStatus::Unlocked,
            secret: SafeBytes(Vec::new()),
            identities: Vec::new(),
        }
    }

    pub fn handle_msg(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        match self.lock_status {
            LockStatus::Unlocked => {
                self.handle_msg_in_unlocked(data)
            },
            LockStatus::Locked => {
                self.handle_msg_in_locked(data)
            },
        }
    }

    fn handle_msg_in_locked(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        use SshAgentRequestType::*;
        let msg_type = data.get(0).ok_or(ErrorKind::TooShort)?;
        let t = SshAgentRequestType::try_from(*msg_type).map_err(|_| ErrorKind::TooShort)?;
        match t {
                Unlock => self.unlock(data),
                RequestIdentities => self.empty_identities(),
                _ => Ok(MessageBuilder::failure())
        }
    }

    fn empty_identities(&mut self) -> Result<MessageBuilder> {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(0);
        Ok(msg)
    }

    fn sign_request(&self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::with_pos(1);
        let key = reader.get_slice(data)?;
        let to_sign = reader.get_slice(data)?;
        let flags = reader.get_u32(data)?;
        let key = self.find_identity(key)?;
        let signature = key.sign(to_sign, flags)?;
        let mut msg = MessageBuilder::new(SshAgentResponseType::SignResponse as u8);
        msg.add_bytes(&signature);

        Ok(msg)
    }

    fn find_identity(&self, key: &[u8]) -> Result<&SshIdentity> {
        self.identities.iter().find(|&e| e.matches(key)).ok_or(ErrorKind::KeyNotFound)
    }

    fn find_position(&self, key: &[u8]) -> Result<usize> {
        self.identities.iter().position(|e| e.matches(key)).ok_or(ErrorKind::KeyNotFound)
    }

    fn list_identities(&mut self) -> Result<MessageBuilder> {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(self.identities.len() as u32);
        for identity in &self.identities {
            msg.add_bytes(&identity.key_type);
            msg.add_str(std::str::from_utf8(&identity.comment).unwrap());
        }

        Ok(msg)
    }

    fn parse_identity(&mut self, data: &[u8]) -> Result<SshIdentity> {
        SshIdentity::from_bytes(data)

    }

    fn add_identity(&mut self, data: &[u8]) -> Result<MessageBuilder> {
       let identity = self.parse_identity(data)?;
       self.identities.push(identity);
        Ok(MessageBuilder::success())
    }

    fn remove_identities(&mut self) -> Result<MessageBuilder> {
        self.identities.clear();
        Ok(MessageBuilder::success())
    }

    fn handle_msg_in_unlocked(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        use SshAgentRequestType::*;
        let msg_type = data.get(0).ok_or(ErrorKind::TooShort)?;

        println!("type {}", msg_type);
        let t = SshAgentRequestType::try_from(*msg_type).map_err(|_| ErrorKind::BadRequestType)?;
        match t {
            Lock =>  self.lock(data),
            RequestIdentities => self.list_identities(),
            RemoveAllIdentities => self.remove_identities(),
            RemoveIdentity => self.remove_identity(data),
            AddIdentity => self.add_identity(data),
            SignRequest => self.sign_request(data),
            Extension => Ok(MessageBuilder::new(SshAgentResponseType::ExtensionFailure as u8)),
            _ => self.unhandled(data)
        }
    }

    fn unhandled(&mut self, _:&[u8]) -> Result<MessageBuilder> {
        Ok(MessageBuilder::failure())
    }

    fn remove_identity(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::with_pos(1);
        let key = reader.get_slice(data)?;
        let i = self.find_position(key)?;
        self.identities.remove(i);
        Ok(MessageBuilder::success())
    }

    fn lock(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::with_pos(1);
        let secret =  reader.get_slice(data)?;
        self.secret.zeroize();
        self.secret.0.clear();
        self.secret.0.extend_from_slice(secret);
        self.lock_status = LockStatus::Locked;
        self.encrypt_store();
        Ok(MessageBuilder::new(SshAgentResponseType::Success as u8))
    }

    fn encrypt_store(&mut self) {
    }

    fn decrypt_store(&mut self) {
    }

    fn unlock(&mut self,  data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::with_pos(1);
        let secret =  reader.get_slice(data)?;
        Ok(if secret != self.secret.0 {
            MessageBuilder::failure()
        } else {
            // Zero out old secret
            self.secret.zeroize();
            self.secret.0.clear();
            self.lock_status = LockStatus::Unlocked;
            self.decrypt_store();
            MessageBuilder::success()
        })
    }
}
