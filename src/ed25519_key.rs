use crate::data_reader::*;
use crate::error::*;
use crate::ssh_agent::*;
use crate::utils::*;

pub struct Ed25519Key {
    key: ed25519_dalek::Keypair,
    id: Vec<u8>,
}

impl TryFromDataReader for Ed25519Key {
    fn try_from_data_reader(r: &mut DataReader<'_>) -> Result<Self> {
        let key_type = r.get_slice()?;
        let public = r.get_slice()?;
        let id = append_parts(&[key_type, public]);
        let private = strip_zero(r.get_slice()?);
        let key =
            ed25519_dalek::Keypair::from_bytes(private).map_err(|_| ErrorKind::KeyNotCreated)?;
        Ok(Ed25519Key { key, id })
    }
}

impl SshSigningKey for Ed25519Key {
    fn sign(&self, _: &SshIdentity, data: &[u8], _: u32) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer;
        Ok(append_parts(&[
            "ssh-ed25519".as_bytes(),
            self.key.sign(data).as_ref(),
        ]))
    }

    fn id(&self) -> &[u8] {
        &self.id
    }
}
