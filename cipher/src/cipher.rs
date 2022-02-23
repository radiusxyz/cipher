use crate::Error;

#[cfg(feature = "canon")]
use canonical_derive::Canon;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_hades::strategies::{ScalarStrategy, Strategy};

use core::ops::Mul;
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR};
use rand_core::OsRng;

#[forbid(unsafe_code)]
use sha3::{Digest, Keccak256};
use std::convert::TryInto;

use std::{fmt, u64, usize};

const MESSAGE_CAPACITY: usize = 2;
const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;
const CIPHER_BYTES_SIZE: usize = CIPHER_SIZE * BlsScalar::SIZE;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Default)]
#[cfg_attr(feature = "canon", derive(Canon))]

/// Encapsulates an encrypted data
pub struct PoseidonCipher {
  cipher: [BlsScalar; CIPHER_SIZE],
}

pub struct BlsScalarInfo {
  pub bls_scalar: BlsScalar,
  byte_length: usize,
}

impl BlsScalarInfo {
  pub const fn new(bls_scalar: BlsScalar, byte_length: usize) -> Self {
    Self { bls_scalar, byte_length }
  }

  pub fn to_bytes(&self) -> [u8; BlsScalar::SIZE] {
    self.bls_scalar.to_bytes()
  }
}

impl fmt::Debug for BlsScalarInfo {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{{blsScalar: {:?}, byteLength: {}}}", self.bls_scalar, self.byte_length)
  }
}

impl Serializable<CIPHER_BYTES_SIZE> for PoseidonCipher {
  type Error = BytesError;

  /// Convert the instance to a bytes representation
  fn to_bytes(&self) -> [u8; Self::SIZE] {
    let mut bytes = [0u8; Self::SIZE];

    self.cipher.iter().enumerate().for_each(|(i, c)| {
      let n = i * BlsScalar::SIZE;
      bytes[n..n + BlsScalar::SIZE].copy_from_slice(&c.to_bytes());
    });

    bytes
  }

  /// Create an instance from a previous `PoseidonCipher::to_bytes` function
  fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
    let mut cipher: [BlsScalar; CIPHER_SIZE] = [BlsScalar::zero(); CIPHER_SIZE];

    for (i, scalar) in cipher.iter_mut().enumerate() {
      let idx = i * BlsScalar::SIZE;
      let len = idx + BlsScalar::SIZE;
      *scalar = BlsScalar::from_slice(&bytes[idx..len])?;
    }

    Ok(Self::new(cipher))
  }
}

impl PoseidonCipher {
  /// [`PoseidonCipher`] constructor
  pub const fn new(cipher: [BlsScalar; CIPHER_SIZE]) -> Self {
    Self { cipher }
  }

  /// Maximum number of scalars allowed per message
  pub const fn capacity() -> usize {
    MESSAGE_CAPACITY
  }

  /// Number of scalars used in a cipher
  pub const fn cipher_size() -> usize {
    CIPHER_SIZE
  }

  /// Number of bytes used by from/to bytes `PoseidonCipher` function
  pub const fn cipher_size_bytes() -> usize {
    CIPHER_BYTES_SIZE
  }

  /// Getter for the cipher
  pub const fn cipher(&self) -> &[BlsScalar; CIPHER_SIZE] {
    &self.cipher
  }

  pub fn initial_state(secret: &JubJubAffine, nonce: BlsScalar) -> [BlsScalar; dusk_hades::WIDTH] {
    [
      BlsScalar::from_raw([0x100000000u64, 0, 0, 0]),          // Domain - Maximum plaintext length of the elements of Fq, as defined in the paper
      BlsScalar::from_raw([MESSAGE_CAPACITY as u64, 0, 0, 0]), // The size of the message is constant because any absent input is replaced by zero
      secret.get_x(),
      secret.get_y(),
      nonce,
    ]
  }

  pub fn encrypt(message: &[BlsScalar], secret: &JubJubAffine, nonce: &BlsScalar) -> Self {
    let zero = BlsScalar::zero();
    let mut strategy = ScalarStrategy::new();
    let mut cipher = [zero; CIPHER_SIZE];

    let mut state = PoseidonCipher::initial_state(secret, *nonce);
    strategy.perm(&mut state);

    (0..MESSAGE_CAPACITY).for_each(|i| {
      state[i + 1] += if i < message.len() { message[i] } else { BlsScalar::zero() };
      cipher[i] = state[i + 1];
    });

    strategy.perm(&mut state);

    cipher[MESSAGE_CAPACITY] = state[1];
    PoseidonCipher::new(cipher)
  }

  pub fn decrypt(&self, secret: &JubJubAffine, nonce: &BlsScalar) -> Result<[BlsScalar; MESSAGE_CAPACITY], Error> {
    let zero = BlsScalar::zero();
    let mut strategy = ScalarStrategy::new();
    let mut message = [zero; MESSAGE_CAPACITY];
    let mut state = PoseidonCipher::initial_state(secret, *nonce);

    strategy.perm(&mut state);

    (0..MESSAGE_CAPACITY).for_each(|i| {
      message[i] = self.cipher[i] - state[i + 1];
      state[i + 1] = self.cipher[i];
    });

    strategy.perm(&mut state);

    if self.cipher[MESSAGE_CAPACITY] != state[1] {
      return Err(Error::CipherDecryptionFailed);
    }

    Ok(message)
  }

  pub fn get_secret_key(y_bytes: &[u8]) -> JubJubAffine {
    let mut hasher = Keccak256::new();

    hasher.update(y_bytes);
    let result = hasher.finalize();
    let y_hash = format!("{:x}", result);
    let secret = y_hash.as_bytes().try_into().expect("Slice with incorrect length");
    let secret = JubJubScalar::from_bytes_wide(&secret);
    GENERATOR.to_niels().mul(&secret).into()
  }

  pub fn convert_nonce(nonce: &[u8; 32]) -> BlsScalar {
    BlsScalar::from_bytes(&nonce).unwrap()
  }

  pub fn gen_nonce() -> BlsScalar {
    BlsScalar::random(&mut OsRng)
  }

  pub fn convert_message_to_bls_scalar(message: &[u8]) -> Vec<BlsScalarInfo> {
    let mut message_vecs: Vec<Vec<u8>> = message.to_vec().chunks(32).map(|s| s.into()).collect();

    // let mut bls_scalars = Vec<BlsScalarInfo>(...);
    let mut bls_scalars = Vec::new();

    for (_, message_vec) in message_vecs.iter_mut().enumerate() {
      //   println!("message_vec.capacity {:?}", message_vec.capacity());
      let byte_length = message_vec.capacity();
      message_vec.resize(32, 0);
      let temp = &*message_vec;
      let message: [u8; 32] = temp.as_slice().try_into().unwrap();
      bls_scalars.push(BlsScalarInfo::new(BlsScalar::from_bytes(&message).unwrap(), byte_length));
    }
    bls_scalars
  }

  pub fn convert_bls_scalar_to_message(bls_scalars: Vec<BlsScalar>) -> Vec<u8> {
    // let mut bls_scalars = Vec<BlsScalarInfo>(...);
    let mut message = Vec::new();

    for (_, bls_scalar) in bls_scalars.iter().enumerate() {
      message.extend_from_slice(&bls_scalar.to_bytes());
    }
    message.try_into().unwrap()
  }

  pub fn generates_messages(bls_scalar_infos: Vec<BlsScalarInfo>) -> Vec<[BlsScalar; PoseidonCipher::capacity()]> {
    let mut messages = Vec::new();
    let mut i = 0;
    // let mut message = ;
    let mut index = 0;
    messages.push([BlsScalar::zero(); PoseidonCipher::capacity()]);

    for (_, bls_scalar_info) in bls_scalar_infos.iter().enumerate() {
      //   println!("bls_scalars: {:?}", k);
      messages[index][i] = bls_scalar_info.bls_scalar;

      // message[i] = bls_scalar_info.bls_scalar;
      i = (i + 1) % PoseidonCipher::capacity();

      if i == 0 {
        index += 1;
        messages.push([BlsScalar::zero(); PoseidonCipher::capacity()]);
      }
    }
    messages
  }
}
