use crate::message_builder::*;
use crate::ssh_agent_types::*;
use crate::data_reader::*;

use zeroize::{Zeroize, ZeroizeOnDrop};
use ed25519_dalek::{Signer};
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

trait SigningKey {
    fn sign(&self, data: &[u8], _flags: u32) -> Option<Vec<u8>>;
    fn matches(&self, key: &[u8]) -> bool;
    fn public_key(&self) -> Option<Vec<u8>>;
    fn verify(&self, sig: &[u8], data: &[u8]) -> bool;
}

pub struct SshIdentity {
    key_type: Vec<u8>,
    key_pair:  ed25519_dalek::Keypair,
    comment: Vec<u8>,
}

impl SshIdentity {
    fn sign(&self, data: &[u8], _flags: u32) -> Option<Vec<u8>> {
        Some(self.key_pair.sign(data).as_ref().to_vec())
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

    pub fn handle_msg(&mut self, data: &[u8]) -> MessageBuilder {
        match self.lock_status {
            LockStatus::Unlocked => {
                self.handle_msg_in_unlocked(data)
            },
            LockStatus::Locked => {
                self.handle_msg_in_locked(data)
            },
        }
    }

    fn handle_msg_in_locked(&mut self, data: &[u8]) -> MessageBuilder {
        if let Ok(t) = SshAgentRequestType::try_from(data[4]) {
            use SshAgentRequestType::*;
            return match t {
                Unlock => self.unlock(data),
                RequestIdentities => self.empty_identities(),
                _ => MessageBuilder::failure(),
            };
        }

        MessageBuilder::failure()
    }

    fn empty_identities(&mut self) -> MessageBuilder {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(0);
        msg
    }

    fn sign_request(&self, data: &[u8]) -> MessageBuilder {
        let mut reader = DataReader::with_pos(5);
        let key = match reader.get_slice(data) {
            Some(v) => v,
            None => return MessageBuilder::failure(),
        };

        let to_sign = match reader.get_slice(data) {
            Some(v) => v,
            None => return MessageBuilder::failure(),
        };

        let flags = match reader.get_u32(data) {
            Some(v) => v,
            None => return MessageBuilder::failure(),
        };

        let key = match self.find_identity(key) {
            Some(k) => k,
            None => return MessageBuilder::failure(),
        };

        let signature = match key.sign(to_sign, flags) {
            Some(s) => s,
            None => return MessageBuilder::failure(),
        };

        let mut msg = MessageBuilder::new(SshAgentResponseType::SignResponse as u8);
        msg.add_sub_message(&[&key.key_type, &signature]);

        msg
    }

    fn find_identity(&self, key: &[u8]) -> Option<&SshIdentity> {
        let mut reader = DataReader::new();
        let _key_type = reader.get_slice(key)?;
        let public = reader.get_slice(key)?;
        self.identities.iter().find(|&e| e.key_pair.public.as_bytes() == public)
    }

    fn find_position(&self, key: &[u8]) -> Option<usize> {
        let mut reader = DataReader::new();
        let _key_type = reader.get_slice(key)?;
        let public = reader.get_slice(key)?;
        self.identities.iter().position(|e| e.key_pair.public.as_bytes() == public)
    }

    fn list_identities(&mut self) -> MessageBuilder {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(self.identities.len() as u32);
        for identity in &self.identities {
            msg.add_sub_message(&[&identity.key_type, identity.key_pair.public.as_bytes()]);
            msg.add_str(std::str::from_utf8(&identity.comment).unwrap());
        }

        msg
    }

    fn parse_identity(&mut self, data: &[u8]) -> Option<SshIdentity> {
        let mut reader = DataReader::with_pos(5);
        let key_type = reader.get_slice(data)?;
        let _public = reader.get_slice(data)?;
        let private = reader.get_slice(data)?;
        let comment = reader.get_slice(data)?;

        Some(SshIdentity{
            key_type: key_type.to_vec(),
            key_pair: ed25519_dalek::Keypair::from_bytes(private).unwrap(),
            comment: comment.to_vec(),
        })
    }

    fn add_identity(&mut self, data: &[u8]) -> MessageBuilder {
        if let Some(identity) = self.parse_identity(data) {
            self.identities.push(identity);
            MessageBuilder::success()
        } else {
            MessageBuilder::failure()
        }
    }

    fn remove_identities(&mut self) -> MessageBuilder {
        self.identities.clear();
        MessageBuilder::success()
    }

    fn handle_msg_in_unlocked(&mut self, data: &[u8]) -> MessageBuilder {
        println!("type {:?}", data[4]);
        if let Ok(t) = SshAgentRequestType::try_from(data[4]) {
            use SshAgentRequestType::*;
            match t {
                Lock =>  self.lock(data),
                Unlock => MessageBuilder::failure(),
                RequestIdentities => self.list_identities(),
                RemoveAllIdentities => self.remove_identities(),
                RemoveIdentity => self.remove_identity(data),
                AddIdentity => self.add_identity(data),
                SignRequest => self.sign_request(data),
                Extension => MessageBuilder::new(SshAgentResponseType::ExtensionFailure as u8),
                _ => self.unhandled(data)
            }
        } else {
            MessageBuilder::failure()
        }
    }

    fn unhandled(&mut self, _:&[u8]) -> MessageBuilder {
        MessageBuilder::failure()
    }

    fn remove_identity(&mut self, data: &[u8]) -> MessageBuilder {
        let mut reader = DataReader::with_pos(5);
        let key = match reader.get_slice(data) {
            Some(v) => v,
            None => return MessageBuilder::failure(),
        };

        if let Some(i) = self.find_position(key) {
            self.identities.remove(i);
            MessageBuilder::success()
        } else {
            MessageBuilder::failure()
        }
    }

    fn lock(&mut self, data: &[u8]) -> MessageBuilder {
        let mut reader = DataReader::with_pos(5);
        match reader.get_slice(data) {
            Some(secret) => {
                self.secret.zeroize();
                self.secret.0.clear();
                self.secret.0.extend_from_slice(secret);
                self.lock_status = LockStatus::Locked;
                self.encrypt_store();
                MessageBuilder::new(SshAgentResponseType::Success as u8)
            },
            None => {
                MessageBuilder::failure()
            },
        }
    }

    fn encrypt_store(&mut self) {
    }

    fn decrypt_store(&mut self) {
    }

    fn unlock(&mut self,  data: &[u8]) -> MessageBuilder {
        let mut reader = DataReader::with_pos(5);
        match reader.get_slice(data) {
            Some(secret) => {
                if secret != self.secret.0 {
                    MessageBuilder::failure()
                } else {
                    // Zero out old secret
                    self.secret.zeroize();
                    self.secret.0.clear();
                    self.lock_status = LockStatus::Unlocked;
                    self.decrypt_store();
                    MessageBuilder::success()
                }
            },
            None => {
                MessageBuilder::failure()
            },
        }
    }
}
