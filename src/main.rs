use std::os::unix::net::UnixStream;

use zeroize::{Zeroize, ZeroizeOnDrop};

mod ssh_agent;
use ssh_agent::*;

#[derive(Zeroize, ZeroizeOnDrop, Debug)]
pub struct SafeBytes(pub Vec<u8>);

enum LockStatus {
	Locked,
	Unlocked,
}

pub struct Indentity {
    key: String,
    comment: String,
}

pub struct SshAgent {
	lock_status: LockStatus,
    secret: SafeBytes,
    identities: Vec<SshIdentity>,
}

pub struct SshIdentity {
    key_type: Vec<u8>,
    public: Vec<u8>,
    private: Vec<u8>,
    comment: Vec<u8>,
}

impl SshAgent {
    pub fn new() -> SshAgent {
        SshAgent {
            lock_status: LockStatus::Unlocked,
            secret: SafeBytes(Vec::new()),
            identities: Vec::new(),
        }
    }

    pub fn handle_msg(&mut self, msg: MessageReader) -> MessageBuilder {
        match self.lock_status {
            LockStatus::Unlocked => {
                self.handle_msg_in_unlocked(msg)
            },
            LockStatus::Locked => {
                self.handle_msg_in_locked(msg)
            },
        }
    }

    fn handle_msg_in_locked(&mut self, msg: MessageReader) -> MessageBuilder {
        if let Ok(t) = SshAgentRequestType::try_from(msg.get_type()) {
            use SshAgentRequestType::*;
            match t {
                Unlock => self.unlock(msg),
                RequestIdentities => self.empty_identities(),
                _ => MessageBuilder::failure(),
            }
        } else {
            MessageBuilder::failure()
        }
    }

    fn empty_identities(&mut self) -> MessageBuilder {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(0);
        msg
    }

    fn list_identities(&mut self, msg: MessageReader) -> MessageBuilder {
        let mut msg = MessageBuilder::new(SshAgentResponseType::IdentitiesAnswer as u8);
        msg.add_u32(self.identities.len() as u32);
        for identity in &self.identities {
//            msg.add_str(&identity.key);
            msg.add_str(std::str::from_utf8(&identity.comment).unwrap());
        }

        msg
    }

    fn parse_identity(&mut self, mut msg: MessageReader) -> Option<SshIdentity> {
        let (key_type, o) = msg.get_slice_at(msg.current_position())?;
        let (private, o) = msg.get_slice_at(o)?;
        let (public, o) = msg.get_slice_at(o)?;
        let (comment, o) = msg.get_slice_at(o)?;

        let out = Some(SshIdentity{
            key_type: key_type.to_vec(),
            public: public.to_vec(),
            private: private.to_vec(),
            comment: comment.to_vec(),
        });
        msg.set_position(o);
        out
    }

    fn add_identity(&mut self, msg: MessageReader) -> MessageBuilder {
        if let Some(identity) = self.parse_identity(msg) {
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

    fn handle_msg_in_unlocked(&mut self, msg: MessageReader) -> MessageBuilder {
        if let Ok(t) = SshAgentRequestType::try_from(msg.get_type()) {
            use SshAgentRequestType::*;
            match t {
                Lock =>  self.lock(msg),
                Unlock => MessageBuilder::failure(),
                RequestIdentities => self.list_identities(msg),
                RemoveAllIdentities => self.remove_identities(),
                Extension => MessageBuilder::new(SshAgentResponseType::ExtensionFailure as u8),
                _ => self.unhandled(msg)
            }
        } else {
            MessageBuilder::failure()
        }
    }

    fn unhandled(&mut self, mut _msg: MessageReader) -> MessageBuilder {
        todo!()
    }

    fn lock(&mut self, mut msg: MessageReader) -> MessageBuilder {
        match msg.get_slice() {
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

    fn unlock(&mut self, mut msg: MessageReader) -> MessageBuilder {
        println!("Got unlock");
        match msg.get_slice() {
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


fn main() {
    println!("Hello, world!");
    let mut builder = MessageBuilder::new(SshAgentRequestType::Lock as u8);
    builder.add_str("secret");
    let msg = MessageReader::new(builder.build().to_vec()).unwrap();
    let mut agent = SshAgent::new();
    agent.handle_msg(msg);
	let (sock1, sock2) = match UnixStream::pair() {
		Ok((sock1, sock2)) => (sock1, sock2),
		Err(e) => {
			println!("Couldn't create a pair of sockets: {e:?}");
			return
		}
	};
}
