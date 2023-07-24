use crate::message_builder::*;
use crate::ssh_agent_types::*;
use crate::data_reader::*;

use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SafeBytes(pub Vec<u8>);
use p256::{
    ecdsa::{SigningKey as EcDsa256SigningKey, Signature as EcDsa256Signature, signature::Signer as EcDsaSigner},
};


enum LockStatus {
	Locked,
	Unlocked,
}

pub struct SshAgent {
	lock_status: LockStatus,
    secret: SafeBytes,
    identities: Vec<SshIdentity>,
}

trait SshSigningKey {
    fn sign(&self, id:&SshIdentity, data: &[u8], _flags: u32) -> Option<Vec<u8>>;
    fn public_key(&self) -> Option<Vec<u8>>;
    fn matches(&self, key: &[u8]) -> bool {
        let mut reader = DataReader::new();
        let _key_type = match reader.get_slice(key) {
            Some(v) => v,
            None => return false,
        };
        let given_public = match reader.get_slice(key) {
            Some(v) => v,
            None => return false,
        };
        let public = match self.public_key() {
            Some(v) => v,
            None => return false,
        };

        given_public == public
    }
}

pub struct Ed25519Key (ed25519_dalek::Keypair);

impl SshSigningKey for Ed25519Key {
    fn sign(&self, id:&SshIdentity, data: &[u8], _flags: u32) -> Option<Vec<u8>> {
        use ed25519_dalek::{Signer};
        Some(
            append_parts(&[
                "ssh-ed25519".as_bytes(),
                self.0.sign(data).as_ref(),
            ])
        )
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.0.public.as_bytes().to_vec())
    }
}

pub struct EcDsaNistP256{
    key: EcDsa256SigningKey,
    curve: Vec<u8>,
}

impl SshSigningKey for EcDsaNistP256 {
    fn sign(&self, id:&SshIdentity, data: &[u8], _flags: u32) -> Option<Vec<u8>> {
        let signature: EcDsa256Signature = self.key.sign(data);
        let (r, s) = signature.split_bytes();
        let mut r = r.to_vec();
        let mut s = s.to_vec();
        let zero = &[0 as u8];
        if r[0] > 127 {
            r.splice(0..0, zero.iter().cloned());
        }

        if s[0] > 127 {
            s.splice(0..0, zero.iter().cloned());
        }

        Some(
            append_parts(&[
                "ecdsa-sha2-nistp256".as_bytes(),
                &append_parts(&[
                    &r,
                    &s,
                ]),
            ]),
        )
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.key.verifying_key().to_sec1_bytes().as_ref().to_vec())
    }

    fn matches(&self, key: &[u8]) -> bool {
        let mut reader = DataReader::new();
        let _key_type = match reader.get_slice(key) {
            Some(v) => v,
            None => return false,
        };
        let _curve_name = match reader.get_slice(key) {
            Some(v) => v,
            None => return false,
        };
        let given_public = match reader.get_slice(key) {
            Some(v) => v,
            None => return false,
        };
        let public = match self.public_key() {
            Some(v) => v,
            None => return false,
        };

        given_public == public
    }
}

mod tests {
    use crate::data_reader::DataReader;
    #[test]
    fn ecdsa_from_bytes() {
        let data:Vec<u8> = vec![0, 0, 0, 191, 17, 0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 58, 68, 147, 51, 129, 229, 156, 162, 158, 117, 204, 245, 191, 121, 45, 224, 246, 89, 22, 221, 168, 199, 116, 54, 234, 139, 8, 23, 183, 182, 206, 22, 42, 2, 36, 106, 70, 236, 156, 36, 26, 14, 208, 99, 52, 190, 147, 241, 246, 9, 4, 250, 82, 21, 146, 221, 77, 237, 85, 193, 131, 255, 149, 253, 0, 0, 0, 33, 0, 129, 90, 137, 12, 208, 73, 28, 145, 249, 129, 220, 225, 18, 93, 170, 223, 49, 174, 54, 188, 55, 6, 54, 101, 21, 202, 154, 93, 105, 120, 254, 183, 0, 0, 0, 45, 114, 111, 111, 116, 64, 49, 55, 50, 45, 49, 48, 53, 45, 49, 48, 49, 45, 49, 55, 48, 46, 105, 112, 46, 108, 105, 110, 111, 100, 101, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109];
        let mut reader = DataReader::with_pos(5);
        let key_type = reader.get_slice(&data).unwrap();
        let key_type_str = std::str::from_utf8(key_type).unwrap();
        assert_eq!(key_type_str, "ecdsa-sha2-nistp256");
        let curve_name = reader.get_slice(&data).unwrap();
        let curve_name_str = std::str::from_utf8(curve_name).unwrap();
        assert_eq!(curve_name_str, "nistp256");
        let q = reader.get_slice(&data).unwrap();
        assert_eq!(q, &[4, 58, 68, 147, 51, 129, 229, 156, 162, 158, 117, 204, 245, 191, 121, 45, 224, 246, 89, 22, 221, 168, 199, 116, 54, 234, 139, 8, 23, 183, 182, 206, 22, 42, 2, 36, 106, 70, 236, 156, 36, 26, 14, 208, 99, 52, 190, 147, 241, 246, 9, 4, 250, 82, 21, 146, 221, 77, 237, 85, 193, 131, 255, 149, 253]);
        let d = reader.get_slice(&data).unwrap();
        assert_eq!(d, [0, 129, 90, 137, 12, 208, 73, 28, 145, 249, 129, 220, 225, 18, 93, 170, 223, 49, 174, 54, 188, 55, 6, 54, 101, 21, 202, 154, 93, 105, 120, 254, 183]);
        let comment = reader.get_slice(&data).unwrap();
        let comment_str = std::str::from_utf8(comment).unwrap();
        assert_eq!(comment_str, "root@172-105-101-170.ip.linodeusercontent.com");
    }
}

pub enum SshKey {
    Ed25519Key(Ed25519Key),
    EcDsaNistP256(EcDsaNistP256),
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
    pub fn from_bytes(data:&[u8]) -> Option<SshIdentity> {
        let mut reader = DataReader::with_pos(5);
        let key_type = reader.get_slice(data)?;
        let key_type_str = std::str::from_utf8(key_type).ok()?;
        match key_type_str {
            "ssh-ed25519" => {
                let public = reader.get_slice(data)?;
                let private = reader.get_slice(data)?;
                let comment = reader.get_slice(data)?;
                Some(SshIdentity{
                    key_type: append_parts(&[key_type, public]),
                    key: SshKey::Ed25519Key(
                        Ed25519Key(
                            ed25519_dalek::Keypair::from_bytes(private).ok()?
                        )
                    ),
                    comment: comment.to_vec(),
                })
            },
            "ecdsa-sha2-nistp256" => {
                let curve_name = reader.get_slice(&data)?;
                let curve_name_str = std::str::from_utf8(curve_name).ok()?;
                let q = reader.get_slice(&data)?;
                let d = reader.get_slice(&data)?;
                if d.len() > 33 || d.len() < 32  {
                    return None;
                }

                let private = if d.len() == 33 { &d[1..] } else {d };
                let comment = reader.get_slice(data)?;
                Some(SshIdentity{
                    key_type: append_parts(&[key_type, curve_name, q]),
                    key: SshKey::EcDsaNistP256(
                        EcDsaNistP256 {
                            key: EcDsa256SigningKey::from_slice(private).ok()?,
                            curve: curve_name.to_vec(),
                        }
                    ),
                    comment: comment.to_vec(),
                })
            },
            _ => None,
        }
    }

    fn sign(&self, data: &[u8], _flags: u32) -> Option<Vec<u8>> {
        match &self.key {
            SshKey::Ed25519Key(key) => key.sign(self, data, _flags),
            SshKey::EcDsaNistP256(key) => key.sign(self, data, _flags),
        }
    }

    fn matches(&self, blob: &[u8]) -> bool {
        match &self.key {
            SshKey::Ed25519Key(key) => key.matches(blob),
            SshKey::EcDsaNistP256(key) => key.matches(blob),
        }
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        match &self.key {
            SshKey::Ed25519Key(key) => key.public_key(),
            SshKey::EcDsaNistP256(key) => key.public_key(),

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
        msg.add_bytes(&signature);

        msg
    }

    fn find_identity(&self, key: &[u8]) -> Option<&SshIdentity> {
        self.identities.iter().find(|&e| e.matches(key))
    }

    fn find_position(&self, key: &[u8]) -> Option<usize> {
        let mut reader = DataReader::new();
        let _key_type = reader.get_slice(key)?;
        let public = reader.get_slice(key)?;
        self.identities.iter().position(|e| e.matches(key))
    }

    fn list_identities(&mut self) -> MessageBuilder {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(self.identities.len() as u32);
        for identity in &self.identities {
            if let Some(public_key ) = identity.public_key() {
                msg.add_bytes(&identity.key_type);
                msg.add_str(std::str::from_utf8(&identity.comment).unwrap());
            }
        }

        msg
    }

    fn parse_identity(&mut self, data: &[u8]) -> Option<SshIdentity> {
        SshIdentity::from_bytes(data)

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
