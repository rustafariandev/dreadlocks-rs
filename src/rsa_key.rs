use crate::data_reader::*;
use crate::error::*;
use crate::ssh_agent::{SshIdentity, SshSigningKey};
use crate::utils::*;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::{Sha256, Sha512};
use rsa::signature::SignatureEncoding;
use rsa::RsaPrivateKey;
use signature::Signer;

pub struct RsaKey {
    key: RsaPrivateKey,
    id: Vec<u8>,
}

impl SshSigningKey for RsaKey {
    fn sign(&self, _id: &SshIdentity, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        match _flags {
            2 => {
                let signing_key: SigningKey<Sha256> = SigningKey::new(self.key.clone());
                let sig = signing_key
                    .try_sign(data)
                    .map_err(|_| ErrorKind::TooShort)?;
                Ok(append_parts(&[b"rsa-sha2-256", &sig.to_vec()]))
            }
            4 => {
                let signing_key: SigningKey<Sha512> = SigningKey::new(self.key.clone());

                let sig = signing_key
                    .try_sign(data)
                    .map_err(|_| ErrorKind::TooShort)?;
                Ok(append_parts(&[b"rsa-sha2-512", &sig.to_vec()]))
            }
            _ => {
                let signing_key: SigningKey<sha1::Sha1> = SigningKey::new(self.key.clone());
                let sig = signing_key
                    .try_sign(data)
                    .map_err(|_| ErrorKind::TooShort)?;
                Ok(append_parts(&[b"ssh-rsa", &add_zero(sig.to_vec())]))
            }
        }
    }

    fn id(&self) -> &[u8] {
        &self.id
    }
}

impl TryFromDataReader for RsaKey {
    fn try_from_data_reader(reader: &mut DataReader<'_>) -> Result<Self> {
        let key_type = reader.get_slice()?;
        let n = reader.get_slice()?;
        let e = reader.get_slice()?;
        let d = strip_zero(reader.get_slice()?);
        reader.skip_slice()?; //Skipping iqpmp
        let p = strip_zero(reader.get_slice()?);
        let q = strip_zero(reader.get_slice()?);
        let id = append_parts(&[key_type, e, n]);
        Ok(RsaKey {
            key: rsa::RsaPrivateKey::from_components(
                rsa::BigUint::from_bytes_be(strip_zero(n)),
                rsa::BigUint::from_bytes_be(strip_zero(e)),
                rsa::BigUint::from_bytes_be(d),
                [
                    rsa::BigUint::from_bytes_be(p),
                    rsa::BigUint::from_bytes_be(q),
                ]
                .to_vec(),
            )
            .map_err(|_| ErrorKind::KeyNotCreated)?,
            id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn try_from() {
        let msg: [u8; 1435] = [
            17, 0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 1, 129, 0, 240, 54, 156, 78,
            156, 34, 30, 251, 207, 88, 81, 58, 224, 174, 21, 133, 45, 225, 74, 12, 241, 7, 146,
            249, 245, 254, 101, 45, 158, 219, 107, 183, 70, 47, 202, 4, 34, 238, 151, 138, 208,
            216, 248, 183, 76, 50, 191, 127, 150, 160, 200, 213, 52, 16, 200, 210, 41, 70, 46, 185,
            197, 163, 213, 160, 151, 155, 241, 35, 122, 52, 214, 22, 15, 246, 104, 219, 213, 152,
            166, 159, 67, 226, 161, 4, 81, 132, 54, 142, 67, 24, 34, 49, 186, 37, 43, 162, 17, 238,
            124, 85, 199, 34, 195, 241, 151, 153, 222, 102, 53, 245, 140, 103, 103, 158, 45, 126,
            84, 40, 223, 186, 69, 10, 109, 182, 9, 100, 231, 255, 47, 195, 238, 47, 203, 93, 215,
            118, 208, 144, 173, 44, 28, 114, 102, 138, 57, 40, 172, 92, 99, 226, 124, 48, 121, 121,
            227, 57, 230, 14, 36, 38, 16, 137, 133, 102, 219, 15, 191, 48, 220, 95, 214, 53, 151,
            82, 207, 248, 252, 68, 86, 226, 4, 0, 181, 107, 250, 116, 46, 172, 234, 122, 246, 59,
            225, 60, 113, 179, 197, 95, 73, 78, 248, 6, 217, 231, 254, 78, 212, 191, 66, 59, 187,
            71, 180, 73, 60, 238, 214, 136, 220, 133, 225, 244, 151, 99, 101, 16, 19, 163, 246, 24,
            185, 213, 149, 230, 152, 16, 227, 206, 0, 29, 1, 107, 124, 244, 48, 218, 20, 230, 152,
            172, 204, 6, 179, 118, 29, 33, 105, 21, 244, 11, 0, 57, 206, 240, 97, 31, 162, 227,
            148, 89, 151, 179, 22, 4, 156, 44, 114, 48, 133, 98, 174, 252, 234, 125, 125, 182, 40,
            16, 2, 240, 28, 216, 179, 251, 130, 248, 144, 231, 246, 35, 56, 233, 48, 37, 113, 168,
            233, 246, 117, 52, 218, 219, 220, 235, 143, 225, 118, 37, 158, 255, 83, 250, 165, 232,
            62, 165, 29, 62, 116, 2, 105, 187, 158, 5, 200, 213, 110, 140, 108, 75, 211, 103, 95,
            48, 66, 1, 30, 204, 148, 60, 62, 193, 182, 72, 175, 31, 189, 115, 79, 253, 125, 230,
            158, 130, 204, 107, 66, 13, 180, 164, 47, 148, 219, 193, 56, 228, 140, 158, 128, 56,
            91, 108, 53, 217, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 128, 40, 113, 105, 91, 170, 217, 235,
            209, 133, 149, 95, 7, 196, 176, 74, 155, 67, 160, 60, 177, 117, 27, 75, 89, 158, 91,
            24, 121, 215, 215, 37, 137, 147, 221, 147, 235, 162, 93, 253, 81, 183, 219, 239, 244,
            28, 118, 38, 219, 186, 102, 147, 169, 161, 188, 121, 179, 56, 147, 194, 102, 48, 170,
            102, 219, 68, 235, 82, 108, 32, 181, 40, 158, 74, 77, 184, 85, 218, 222, 122, 159, 49,
            244, 196, 27, 80, 6, 44, 145, 67, 38, 155, 11, 56, 69, 237, 212, 185, 164, 39, 118,
            225, 178, 46, 191, 76, 64, 241, 186, 207, 182, 233, 206, 183, 25, 96, 155, 118, 91,
            243, 95, 15, 36, 180, 88, 3, 184, 227, 126, 137, 114, 57, 117, 254, 141, 108, 43, 106,
            238, 16, 217, 238, 104, 44, 111, 117, 52, 45, 224, 216, 72, 87, 148, 105, 191, 101,
            204, 103, 185, 85, 200, 186, 220, 12, 131, 198, 186, 29, 252, 129, 253, 248, 184, 201,
            35, 126, 52, 115, 116, 166, 20, 35, 140, 98, 255, 45, 9, 198, 154, 2, 88, 117, 128, 71,
            222, 167, 103, 235, 204, 161, 212, 89, 254, 80, 215, 125, 29, 232, 252, 165, 98, 64,
            84, 170, 82, 89, 158, 103, 62, 176, 157, 232, 199, 90, 14, 4, 50, 240, 18, 197, 6, 65,
            156, 95, 126, 66, 38, 214, 177, 92, 24, 17, 174, 184, 59, 121, 81, 162, 7, 183, 199,
            195, 122, 229, 9, 121, 69, 152, 163, 207, 229, 59, 210, 96, 208, 130, 242, 73, 156,
            183, 53, 9, 145, 90, 242, 20, 60, 25, 164, 231, 208, 156, 229, 79, 45, 79, 70, 174, 51,
            111, 81, 214, 188, 108, 37, 88, 203, 242, 163, 200, 129, 128, 90, 40, 10, 144, 79, 99,
            154, 132, 171, 226, 248, 68, 191, 33, 56, 100, 234, 68, 59, 131, 197, 21, 77, 172, 21,
            158, 92, 187, 40, 148, 33, 247, 46, 240, 31, 235, 55, 166, 213, 178, 211, 227, 245,
            213, 188, 160, 98, 151, 224, 117, 190, 134, 122, 38, 238, 202, 83, 244, 54, 62, 9, 245,
            158, 70, 96, 1, 172, 237, 204, 132, 146, 111, 68, 60, 104, 202, 30, 209, 196, 252, 100,
            197, 161, 0, 0, 0, 192, 102, 33, 107, 219, 231, 22, 198, 139, 202, 0, 32, 67, 87, 14,
            159, 83, 76, 148, 78, 254, 180, 250, 68, 29, 89, 219, 229, 140, 226, 15, 98, 18, 235,
            121, 177, 13, 172, 116, 118, 216, 26, 196, 49, 211, 120, 8, 246, 6, 114, 85, 54, 21,
            50, 254, 125, 98, 151, 123, 216, 196, 244, 32, 11, 167, 236, 53, 29, 223, 64, 209, 85,
            32, 7, 94, 139, 132, 102, 204, 131, 177, 86, 162, 232, 37, 75, 85, 168, 88, 91, 61,
            226, 187, 33, 173, 98, 189, 177, 247, 13, 12, 226, 122, 133, 41, 135, 18, 172, 91, 218,
            54, 155, 9, 146, 210, 33, 169, 18, 81, 231, 145, 70, 115, 187, 111, 161, 190, 13, 205,
            216, 30, 132, 223, 103, 68, 212, 154, 41, 96, 179, 81, 165, 52, 117, 170, 115, 29, 203,
            84, 99, 100, 196, 63, 175, 90, 43, 169, 202, 182, 4, 7, 87, 46, 100, 93, 48, 132, 225,
            85, 70, 97, 214, 246, 141, 191, 40, 74, 204, 254, 80, 190, 14, 237, 211, 236, 195, 237,
            90, 11, 177, 148, 192, 113, 0, 0, 0, 193, 0, 255, 209, 169, 63, 40, 119, 71, 242, 55,
            1, 63, 58, 31, 12, 236, 42, 34, 164, 61, 106, 37, 92, 235, 130, 239, 35, 176, 249, 227,
            158, 55, 121, 72, 151, 86, 227, 134, 55, 117, 150, 223, 90, 40, 131, 118, 184, 157,
            251, 143, 12, 78, 77, 22, 0, 4, 206, 197, 204, 3, 31, 183, 162, 143, 224, 220, 42, 215,
            215, 157, 199, 123, 196, 25, 117, 176, 174, 96, 255, 130, 148, 218, 35, 60, 98, 173,
            45, 172, 83, 206, 128, 162, 77, 158, 106, 129, 211, 120, 187, 182, 38, 179, 148, 249,
            234, 145, 179, 170, 243, 223, 205, 108, 157, 73, 254, 68, 227, 222, 167, 147, 1, 50,
            215, 95, 68, 135, 235, 20, 228, 86, 9, 78, 31, 103, 110, 49, 233, 6, 84, 78, 129, 233,
            95, 47, 49, 131, 117, 114, 163, 204, 175, 204, 161, 191, 62, 251, 161, 8, 172, 43, 38,
            152, 143, 90, 223, 182, 86, 65, 0, 81, 60, 159, 249, 194, 151, 70, 162, 91, 100, 213,
            142, 4, 36, 135, 102, 34, 133, 174, 116, 74, 40, 244, 245, 0, 0, 0, 193, 0, 240, 98,
            31, 102, 75, 10, 78, 22, 165, 6, 166, 239, 17, 98, 182, 92, 212, 66, 172, 229, 86, 180,
            234, 88, 89, 61, 139, 197, 80, 100, 177, 140, 226, 55, 6, 149, 137, 60, 241, 55, 150,
            132, 59, 23, 187, 32, 140, 70, 229, 252, 195, 248, 81, 160, 126, 56, 91, 32, 95, 106,
            74, 25, 25, 235, 20, 120, 242, 224, 239, 73, 38, 202, 191, 152, 53, 36, 133, 244, 6,
            197, 80, 210, 32, 125, 219, 209, 77, 149, 180, 103, 197, 69, 195, 116, 91, 39, 195, 75,
            201, 87, 8, 122, 214, 108, 88, 101, 44, 195, 6, 157, 19, 190, 135, 172, 104, 251, 240,
            1, 110, 235, 203, 21, 172, 239, 98, 67, 203, 18, 199, 92, 46, 143, 223, 137, 117, 71,
            97, 54, 198, 218, 152, 237, 132, 189, 80, 196, 61, 59, 151, 175, 194, 55, 202, 219, 60,
            240, 250, 207, 120, 118, 9, 38, 241, 195, 92, 216, 225, 166, 77, 214, 57, 46, 153, 218,
            122, 43, 0, 78, 191, 160, 4, 226, 137, 49, 107, 210, 169, 126, 82, 71, 14, 213, 0, 0,
            0, 45, 114, 111, 111, 116, 64, 49, 55, 50, 45, 49, 48, 53, 45, 49, 48, 49, 45, 49, 55,
            48, 46, 105, 112, 46, 108, 105, 110, 111, 100, 101, 117, 115, 101, 114, 99, 111, 110,
            116, 101, 110, 116, 46, 99, 111, 109,
        ];
        let mut reader = DataReader::new(&msg);
        reader.skip_u8().unwrap();
        let rsa = RsaKey::try_from_data_reader(&mut reader).unwrap();
        let comment = unsafe { std::str::from_utf8_unchecked(reader.get_slice().unwrap()) };
    }
}