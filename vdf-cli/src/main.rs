#![forbid(unsafe_code)]
use hex;
use std::str;

#[macro_use]
extern crate clap;

use cipher::PoseidonCipher;
use dusk_bytes::Serializable;
use rsa_vdf::{SetupForVDF, UnsolvedVDF};
use std::convert::TryInto;
use std::u64;

macro_rules! gen_validator {
  ($name:ident : $type:ty) => {
    gen_validator!($name, str::parse::<$type>);
  };
  ($name:ident, $expr:expr) => {
    fn $name(obj: String) -> Result<(), String> {
      $expr(&obj).map(drop).map_err(|x| format!("{}", x))
    }
  };
}

gen_validator!(is_u16_ok: u16);

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedInfo {
  #[serde(default)]
  pub message_length: usize,
  #[serde(default)]
  pub nonce: String,
  #[serde(default)]
  pub original_text: String,
  #[serde(default)]
  pub cipher_text: Vec<String>,
  #[serde(default)]
  pub x: String,
  #[serde(default)]
  pub t: String,
  #[serde(default)]
  pub p: String,
  #[serde(default)]
  pub q: String,
  #[serde(default)]
  pub n: String,
}

use std::time::Instant;

fn main() {
  use curv::arithmetic::{BigInt, Converter};
  // use curv::BigInt as curvBigInt;

  let matches = clap_app!(vdf =>
    (version: crate_version!())
    (author: "Formula Zero")
    (about: "Encryption and decryption using VDF(Verifiable Delay Functions) & PoseidonCipher")
    (@arg LENGTH: -l --length +takes_value {is_u16_ok} "Length in bits of the discriminant (default: 2048)")
    (@arg VERBOSE: -v --verbose "Log verbosely to stderr.  This command does not currently log anything, so this option currently has no affect.")
    (@arg ACTION_TYPE: +required "encrypt / decrypt" )
    (@arg DATA: +required "Json data" )
  )
  .get_matches();

  let data: &str = matches.value_of("DATA").unwrap();
  let encrypted_info: EncryptedInfo = serde_json::from_str(data).unwrap();
  let action_type: &str = matches.value_of("ACTION_TYPE").unwrap();

  if action_type == "encrypt" {
    let tx = encrypted_info.original_text.as_bytes();
    let message_length = tx.len();
    let bls_scalars = PoseidonCipher::convert_message_to_bls_scalar(&tx);
    let messages = PoseidonCipher::generates_messages(bls_scalars);
    let nonce = PoseidonCipher::gen_nonce();
    let t = BigInt::from_hex(&encrypted_info.t).unwrap();

    let (x, p, q, n) = SetupForVDF::get_rsa_modulus();
    // println!("x: {:?}", &x);
    // println!("t: {:?}", &t);
    // println!("n: {:?}", &n);

    let start = Instant::now();
    let unsolved_vdf = SetupForVDF::public_setup2(&x, &t, &p, &q);
    let solved_vdf_with_trapdoor = UnsolvedVDF::eval_with_trapdoor(&unsolved_vdf);
    let _duration = start.elapsed();
    // println!("Time elapsed in expensive_function() is: {:?}", duration);
    // println!("t: {:?}\n", &unsolved_vdf.setup.t.to_hex());

    let y = solved_vdf_with_trapdoor.y.to_bytes();
    let secret_key = PoseidonCipher::get_secret_key(&y);
    // println!("secret_key: {:?}", &secret_key);

    let mut cipher_hexes = Vec::new();

    for (_i, message) in messages.iter().enumerate() {
      let cipher = PoseidonCipher::encrypt(&*message, &secret_key, &nonce);
      let cipher_bytes = cipher.to_bytes();
      cipher_hexes.push(hex::encode(cipher_bytes));
    }

    let mut result = Vec::new();
    for (_i, cipher_hex) in cipher_hexes.iter().enumerate() {
      let restored_cipher = PoseidonCipher::from_bytes(&hex::decode(cipher_hex).unwrap().try_into().unwrap()).unwrap();
      let decrypt = restored_cipher.decrypt(&secret_key, &nonce);
      result.extend_from_slice(&decrypt.unwrap());
    }

    let mut message = PoseidonCipher::convert_bls_scalar_to_message(result);
    message.resize(message_length, 0);

    // println!("{{\"p\": {:?}, \"q\": {:?}, \"n\": {:?}}}", p.to_hex(), q.to_hex(), n.to_hex());

    println!(
      "{{\"message_length\": {}, \"nonce\": {:?}, \"x\": {:?}, \"t\": {:?}, \"n\": {:?}, \"cipher_text\": {:?}}}",
      message_length,
      hex::encode(nonce.to_bytes()),
      x.to_hex(),
      t.to_hex(),
      n.to_hex(),
      cipher_hexes,
    );
  } else if action_type == "decrypt" {
    let message_length = encrypted_info.message_length;
    let nonce: [u8; 32] = hex::decode(encrypted_info.nonce).unwrap().try_into().expect("Slice with incorrect length");
    let nonce = PoseidonCipher::convert_nonce(&nonce);

    let x = BigInt::from_hex(&encrypted_info.x).unwrap();
    let t = BigInt::from_hex(&encrypted_info.t).unwrap();
    let n = BigInt::from_hex(&encrypted_info.n).unwrap();
    // println!("x: {:?}", &x);
    // println!("t: {:?}", &t);
    // println!("n: {:?}", &n);

    let start = Instant::now();
    let unsolved_vdf = SetupForVDF::public_setup3(&x, &t, &n);
    let solved_vdf = UnsolvedVDF::eval(&unsolved_vdf);
    let _duration = start.elapsed();
    // println!("Time elapsed in expensive_function() is: {:?}", duration);

    let y = solved_vdf.y.to_bytes();
    let secret_key = PoseidonCipher::get_secret_key(&y);
    // println!("secret_key: {:?}", &secret_key);

    let mut result = Vec::new();

    for (_i, cipher_hex) in encrypted_info.cipher_text.iter().enumerate() {
      let restored_cipher = PoseidonCipher::from_bytes(&hex::decode(cipher_hex).unwrap().try_into().unwrap()).unwrap();
      let decrypt = restored_cipher.decrypt(&secret_key, &nonce);
      result.extend_from_slice(&decrypt.unwrap());
    }

    let mut message = PoseidonCipher::convert_bls_scalar_to_message(result);
    message.resize(message_length, 0);

    let result = str::from_utf8(&message[..]).unwrap();

    print!("{:?}", &result);
  }
}
