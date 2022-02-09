#![deny(warnings)]

mod cipher;
mod error;

pub use cipher::PoseidonCipher;

pub use error::Error;

pub trait Cipher {
    //     fn encrypt(message: &[BlsScalar], secret: &JubJubAffine, nonce: &BlsScalar) -> Self;

    //     fn decrypt(
    //         &self,
    //         secret: &JubJubAffine,
    //         nonce: &BlsScalar,
    //     ) -> Result<[BlsScalar; MESSAGE_CAPACITY], Error>;
}
