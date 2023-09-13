use crate::data_reader::*;
use crate::ssh_agent::{SshIdentity, SshSigningKey};

use crate::error::*;
use crate::utils::*;

use elliptic_curve::{
    generic_array::ArrayLength,
    ops::Invert,
    point::PointCompression,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    subtle::CtOption,
    AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, Scalar,
};

use ecdsa::{
    hazmat::{DigestPrimitive, SignPrimitive},
    Signature, SignatureSize, SigningKey,
};

use signature::Signer;

pub trait EsDsaCurve: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression { }

impl<C> EsDsaCurve for C where C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression, { }

pub struct EcDsaKey<C>
where
    C: EsDsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    key: ecdsa::SigningKey<C>,
    id: Vec<u8>,
    curve: Vec<u8>,
}

impl<C> EcDsaKey<C>
where
    C: EsDsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub fn new(key: ecdsa::SigningKey<C>, id: Vec<u8>, curve: Vec<u8>) -> Self {
        Self { key, id, curve }
    }
}

impl<C> TryFromDataReader for EcDsaKey<C>
where
    C: EsDsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn try_from_data_reader(r: &mut DataReader<'_>) -> Result<Self> {
        let key_type = r.get_slice()?;
        let curve_name = r.get_slice()?;
        let q = r.get_slice()?;
        let d = r.get_slice()?;
        let private = strip_zero(d);
        let id = append_parts(&[key_type, curve_name, q]);
        let signing_key: SigningKey<C> =
            SigningKey::from_slice(private).map_err(|_| ErrorKind::KeyNotCreated)?;
        Ok(EcDsaKey::new(signing_key, id, key_type.to_vec()))
    }
}

impl<C> SshSigningKey for EcDsaKey<C>
where
    C: EsDsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn sign(&self, _id: &SshIdentity, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        let signature: Signature<C> = self.key.sign(data);
        let (r, s) = signature.split_bytes();
        let r = add_zero(r.to_vec());
        let s = add_zero(s.to_vec());

        Ok(append_parts(&[&self.curve, &append_parts(&[&r, &s])]))
    }

    fn id(&self) -> &[u8] {
        &self.id
    }
}
