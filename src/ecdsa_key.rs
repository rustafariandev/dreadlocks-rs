use crate::data_reader::*;
use crate::ssh_agent::{
    append_parts,
    SshIdentity,
    SshSigningKey,
};

use crate::error::Result;

use elliptic_curve::{
    point::PointCompression,
    generic_array::ArrayLength,
    ops::Invert,
    subtle::{CtOption},
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
    CurveArithmetic, FieldBytesSize, PrimeCurve, Scalar,
    AffinePoint,
};

use ecdsa::{
    SignatureSize,
    Signature,
    hazmat::{DigestPrimitive, SignPrimitive},
};

use signature::{ Signer };


pub struct EcDsaKey<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,

{
    key: ecdsa::SigningKey<C>,
    curve: Vec<u8>,
    curve_name: Vec<u8>,
}

impl<C> EcDsaKey<C> 
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize, {
        pub fn new(key: ecdsa::SigningKey<C>, curve:Vec<u8>, curve_name: Vec<u8>) -> Self {
            Self {
                key,
                curve,
                curve_name,
            }
        }
}

impl<C> SshSigningKey for EcDsaKey<C> 
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive + PointCompression,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn sign(&self, _id:&SshIdentity, data: &[u8], _flags: u32) -> Result<Vec<u8>> {
        let signature: Signature<C> = self.key.sign(data);
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

        Ok(
            append_parts(&[
                &self.curve,
                &append_parts(&[
                    &r,
                    &s,
                ]),
            ]),
        )
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        Ok(self.key.verifying_key().to_sec1_bytes().as_ref().to_vec())
    }

    fn matches(&self, key: &[u8]) -> bool {
        let mut reader = DataReader::new();
        let _key_type = match reader.get_slice(key) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let _curve_name = match reader.get_slice(key) {
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

