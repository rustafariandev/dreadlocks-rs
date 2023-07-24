use crate::data_reader::*;
use crate::error::*;
use crate::ssh_agent::*;
use crate::utils::*;
use sha1::Digest;
use signature::DigestSigner;
pub struct DsaKey {
    key: dsa::SigningKey,
    id: Vec<u8>,
}

impl TryFromDataReader for DsaKey {
    fn try_from_data_reader(reader: &mut DataReader<'_>) -> Result<Self> {
        let key_type = reader.get_slice()?;
        let p = reader.get_slice()?;
        let q = reader.get_slice()?;
        let g = reader.get_slice()?;
        let y = reader.get_slice()?;
        let x = reader.get_slice()?;
        let verifying_key = dsa::VerifyingKey::from_components(
            dsa::Components::from_components(
                dsa::BigUint::from_bytes_be(strip_zero(p)),
                dsa::BigUint::from_bytes_be(strip_zero(q)),
                dsa::BigUint::from_bytes_be(strip_zero(g)),
            )?,
            dsa::BigUint::from_bytes_be(strip_zero(y)),
        )?;
        let key = dsa::SigningKey::from_components(
            verifying_key,
            dsa::BigUint::from_bytes_be(strip_zero(x)),
        )?;

        let id = append_parts(&[key_type, p, q, g, y]);
        Ok(DsaKey { key, id })
    }
}

impl SshSigningKey for DsaKey {
    fn sign(&self, _id: &SshIdentity, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        let digest = sha1::Sha1::new_with_prefix(data);
        let sig = self.key.try_sign_digest(digest)?;
        let mut data = [0_u8; 40];
        let r = sig.r().to_bytes_be();
        let offset: usize = 20 - r.len();
        data[offset..offset + 20].copy_from_slice(&r);
        let s = sig.s().to_bytes_be();
        let offset: usize = 40 - s.len();
        data[offset..offset + 20].copy_from_slice(&s);
        Ok(append_parts(&[b"ssh-dss", &data]))
    }

    fn id(&self) -> &[u8] {
        &self.id
    }
}
