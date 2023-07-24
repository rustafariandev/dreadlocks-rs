use crate::data_reader::*;
use crate::dsa_key::DsaKey;
use crate::ecdsa_key::EcDsaKey;
use crate::ed25519_key::Ed25519Key;
use crate::error::*;
use crate::message_builder::*;
use crate::rsa_key::RsaKey;
use crate::ssh_agent_types::*;
use std::time::Duration;
use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SafeBytes(pub Vec<u8>);

enum Constraint {
    MaxTime(std::time::Instant),
    Confirm,
    MaxSign(u32),
}

impl TryFromDataReader for Vec<Constraint> {
    fn try_from_data_reader(r: &mut DataReader<'_>) -> Result<Vec<Constraint>> {
        use ConstraintType::*;
        let mut contraints = Vec::new();
        while r.more() {
            match ConstraintType::try_from(r.get_u8()?).map_err(|_| ErrorKind::Unsupported)? {
                Lifetime => {
                    let dur = Duration::from_secs(r.get_u32()? as u64);
                    let t = std::time::Instant::now()
                        .checked_add(dur)
                        .ok_or(ErrorKind::Parse)?;
                    contraints.push(Constraint::MaxTime(t));
                }
                Confirm => {
                    contraints.push(Constraint::Confirm);
                }
                Maxsign => {
                    contraints.push(Constraint::MaxSign(r.get_u32()?));
                }
                Extension => {
                    return Err(ErrorKind::Unsupported);
                }
            }
        }
        Ok(contraints)
    }
}

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
    fn sign(&self, id: &SshIdentity, data: &[u8], _flags: u32) -> Result<Vec<u8>>;
    fn id(&self) -> &[u8];
}

pub struct SshSigningKeyInfo<T: SshSigningKey> {
    key: T,
    comment: Vec<u8>,
    id: Vec<u8>,
    constraints: Vec<Constraint>,
}

impl<T> TryFromDataReader for SshSigningKeyInfo<T>
where
    T: TryFromDataReader + SshSigningKey,
{
    fn try_from_data_reader(r: &mut DataReader<'_>) -> Result<Self> {
        let key = T::try_from_data_reader(r)?;
        let id = key.id().to_vec();
        let comment = r.get_slice()?.to_vec();
        let constraints = <Vec<Constraint>>::try_from_data_reader(r)?;
        Ok(Self {
            key,
            comment,
            id,
            constraints,
        })
    }
}

pub enum SshKey {
    Ed25519Key(Ed25519Key),
    EcDsaNistP256(EcDsaKey<p256::NistP256>),
    EcDsaNistP384(EcDsaKey<p384::NistP384>),
    RsaKey(RsaKey),
    DsaKey(DsaKey),
}

pub struct SshIdentity {
    key_type: Vec<u8>,
    comment: Vec<u8>,
    key: SshKey,
    constraints: Vec<Constraint>,
}

struct IdentityItem<'a> {
    id: &'a [u8],
    comment: &'a [u8],
}

impl SshIdentity {
    pub fn from_bytes(data: &[u8]) -> Result<SshIdentity> {
        let mut reader = DataReader::new(data);
        reader.skip_u8()?;
        let key_type = reader.peek_slice()?;
        match key_type {
            b"ssh-ed25519" => {
                let info = SshSigningKeyInfo::<Ed25519Key>::try_from_data_reader(&mut reader)?;
                Ok(SshIdentity {
                    key_type: info.id,
                    key: SshKey::Ed25519Key(info.key),
                    comment: info.comment,
                    constraints: info.constraints,
                })
            }
            b"ecdsa-sha2-nistp256" => {
                let info = SshSigningKeyInfo::<EcDsaKey<p256::NistP256>>::try_from_data_reader(
                    &mut reader,
                )?;
                Ok(SshIdentity {
                    key_type: info.id,
                    key: SshKey::EcDsaNistP256(info.key),
                    comment: info.comment,
                    constraints: info.constraints,
                })
            }
            b"ecdsa-sha2-nistp384" => {
                let info = SshSigningKeyInfo::<EcDsaKey<p384::NistP384>>::try_from_data_reader(
                    &mut reader,
                )?;
                Ok(SshIdentity {
                    key_type: info.id,
                    key: SshKey::EcDsaNistP384(info.key),
                    comment: info.comment,
                    constraints: info.constraints,
                })
            }
            b"ssh-rsa" => {
                let info = SshSigningKeyInfo::<RsaKey>::try_from_data_reader(&mut reader)?;
                Ok(SshIdentity {
                    key_type: info.id,
                    key: SshKey::RsaKey(info.key),
                    comment: info.comment,
                    constraints: info.constraints,
                })
            }
            b"ssh-dss" => {
                let info = SshSigningKeyInfo::<DsaKey>::try_from_data_reader(&mut reader)?;
                Ok(SshIdentity {
                    key_type: info.id,
                    key: SshKey::DsaKey(info.key),
                    comment: info.comment,
                    constraints: info.constraints,
                })
            }
            _ => Err(ErrorKind::TypeNotFound),
        }
    }

    fn sign(&self, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        match &self.key {
            SshKey::Ed25519Key(key) => key.sign(self, data, _flags),
            SshKey::EcDsaNistP256(key) => key.sign(self, data, _flags),
            SshKey::EcDsaNistP384(key) => key.sign(self, data, _flags),
            SshKey::RsaKey(key) => key.sign(self, data, _flags),
            SshKey::DsaKey(key) => key.sign(self, data, _flags),
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
            LockStatus::Unlocked => self.handle_msg_in_unlocked(data),
            LockStatus::Locked => self.handle_msg_in_locked(data),
        }
    }

    fn handle_msg_in_locked(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        use SshAgentRequestType::*;
        let msg_type = data.first().ok_or(ErrorKind::TooShort)?;
        let t = SshAgentRequestType::try_from(*msg_type).map_err(|_| ErrorKind::TooShort)?;
        match t {
            Unlock => self.unlock(data),
            RequestIdentities => self.empty_identities(),
            _ => Ok(MessageBuilder::failure()),
        }
    }

    fn empty_identities(&mut self) -> Result<MessageBuilder> {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(0);
        Ok(msg)
    }

    fn sign_request(&self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::new(data);
        reader.skip_u8()?;
        let key = reader.get_slice()?;
        let to_sign = reader.get_slice()?;
        let flags = reader.get_u32()?;
        let key = self.find_identity(key)?;
        let signature = key.sign(to_sign, flags)?;
        let mut msg = MessageBuilder::new(SshAgentResponseType::SignResponse as u8);
        msg.add_bytes(&signature);

        Ok(msg)
    }

    fn find_identity(&self, key: &[u8]) -> Result<&SshIdentity> {
        self.identities
            .iter()
            .find(|&e| e.key_type == key)
            .ok_or(ErrorKind::KeyNotFound)
    }

    fn find_position(&self, key: &[u8]) -> Result<usize> {
        self.identities
            .iter()
            .position(|e| e.key_type == key)
            .ok_or(ErrorKind::KeyNotFound)
    }

    fn list_identities(&mut self) -> Result<MessageBuilder> {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        let list: Vec<IdentityItem<'_>> = self
            .identities
            .iter()
            .filter(|i| true)
            .map(|i| IdentityItem {
                id: &i.key_type,
                comment: &i.comment,
            })
            .collect();
        msg.add_u32(list.len() as u32);
        for i in list {
            msg.add_bytes(i.id);
            msg.add_bytes(i.comment);
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
        let msg_type = data.first().ok_or(ErrorKind::TooShort)?;
        let t = SshAgentRequestType::try_from(*msg_type).map_err(|_| ErrorKind::BadRequestType)?;
        match t {
            Lock => self.lock(data),
            RequestIdentities => self.list_identities(),
            RemoveAllIdentities => self.remove_identities(),
            RemoveIdentity => self.remove_identity(data),
            AddIdentity => self.add_identity(data),
            SignRequest => self.sign_request(data),
            Extension => self.extension(data),
            _ => self.unhandled(data),
        }
    }

    fn extension(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::new(data);
        reader.skip_u8()?;
        let extension = reader.get_slice()?;
        match extension {
            b"query" => {
                let mut msg = MessageBuilder::success();
                msg.add_str("query");
                msg.add_str("session-bind@openssh.com");
                Ok(msg)
            }
            b"session-bind@openssh.com" => self.openssh_com_session_bind(&mut reader),
            _ => Ok(MessageBuilder::new(
                SshAgentResponseType::ExtensionFailure as u8,
            )),
        }
    }

    fn openssh_com_session_bind(&mut self, r: &mut DataReader) -> Result<MessageBuilder> {
        let key = r.get_slice()?;
        let sid = r.get_slice()?;
        let sig = r.get_slice()?;
        let fwd = r.get_bool()?;
        Ok(MessageBuilder::new(
            SshAgentResponseType::ExtensionFailure as u8,
        ))
    }

    fn unhandled(&mut self, _: &[u8]) -> Result<MessageBuilder> {
        Ok(MessageBuilder::failure())
    }

    fn remove_identity(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::new(data);
        reader.skip_u8()?;
        let key = reader.get_slice()?;
        let i = self.find_position(key)?;
        self.identities.remove(i);
        Ok(MessageBuilder::success())
    }

    fn lock(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::new(data);
        reader.skip_u8()?;
        let secret = reader.get_slice()?;
        self.secret.zeroize();
        self.secret.0.clear();
        self.secret.0.extend_from_slice(secret);
        self.lock_status = LockStatus::Locked;
        self.encrypt_store();
        Ok(MessageBuilder::success())
    }

    fn encrypt_store(&mut self) {}

    fn decrypt_store(&mut self) {}

    fn unlock(&mut self, data: &[u8]) -> Result<MessageBuilder> {
        let mut reader = DataReader::new(data);
        reader.skip_u8()?;
        let secret = reader.get_slice()?;
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
