// Copyright 2018 Chia Network Inc and POA Networks Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![forbid(unsafe_code)]
use hex;

use std::str;


#[macro_use]
extern crate clap;

use cipher::PoseidonCipher;
use dusk_bytes::Serializable;
use std::convert::TryInto;
use std::{cell::RefCell, fs::File, io::Read, rc::Rc, u64};
use vdf::{InvalidProof, PietrzakVDFParams, VDFParams, WesolowskiVDFParams, VDF};

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
gen_validator!(is_u64_ok: u64);
gen_validator!(is_hex_ok, hex::decode);

fn check_iterations(is_pietrzak: bool, matches: &clap::ArgMatches<'_>) -> u64 {
    let iterations = value_t!(matches, "NUM_ITERATIONS", u64).unwrap();
    if is_pietrzak && (iterations & 1 != 0 || iterations < 66) {
        clap::Error::with_description(
            "Number of iterations must be even and at least 66",
            clap::ErrorKind::ValueValidation,
        )
        .exit()
    } else {
        iterations
    }
}


use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Serialize, Deserialize, Debug)]
struct Stompesi {
  #[serde(default)] pub message_length: usize,
  #[serde(default)] pub nonce: String,
  #[serde(default)] pub original_text: String,
  #[serde(default)] pub cipher_text: Vec<String>,
  pub x: String,
  pub t: u64,
}


fn main() {
  let validate_proof_type = |x| {
      if x == "pietrzak" || x == "wesolowski" {
          Ok(())
      } else {
          Err("Invalid proof type".to_owned())
      }
  };

  let matches = clap_app!(vdf =>
    (version: crate_version!())
    (author: "Formula Zero")
    (about: "Encryption and decryption using VDF(Verifiable Delay Functions) & PoseidonCipher")
    
    (@arg TYPE: -t --type +takes_value {validate_proof_type} "The type of proof to generate")
    (@arg LENGTH: -l --length +takes_value {is_u16_ok} "Length in bits of the discriminant (default: 2048)")

    (@arg VERBOSE: -v --verbose "Log verbosely to stderr.  This command does not currently log anything, so this option currently has no affect.")
    
    (@arg ACTION_TYPE: +required "encrypt / decrypt" )

    (@arg DATA: +required "Json data" )
    // (@arg NUM_ITERATIONS: +required {is_u64_ok} "The number of iterations")
    // (@arg MESSAGE: +required "The message which can be raw tx or encoded tx")
    // (@arg NONCE: "The nonce for decryption")
  ).get_matches();

  let data = r#"{"x": "aa1234", "t": 1000, "original_text": "hi_stompesi" }"#;
  let data: &str = matches.value_of("DATA").unwrap();
//   println!("data: {:?}", &data);
  let data: Stompesi = serde_json::from_str(data).unwrap();;

  let is_pietrzak = matches.value_of("TYPE").map(|x| x == "pietrzak").unwrap_or(false);
  let action_type: &str = matches.value_of("ACTION_TYPE").unwrap();
  let int_size_bits: u16 = matches.value_of("LENGTH").unwrap_or("2048").parse().unwrap();

  let vdf: Box<dyn VDF> = if is_pietrzak {
    Box::new(PietrzakVDFParams(int_size_bits).new()) as _
  } else {
    Box::new(WesolowskiVDFParams(int_size_bits).new()) as _
  };

  if action_type == "encrypt" {
    let tx = data.original_text.as_bytes();
    // println!("tx: {:?}", &data.original_text);

    let message_length = tx.len();
    let bls_scalars = PoseidonCipher::convert_message_to_bls_scalar(&tx);
    let message = PoseidonCipher::convert_bls_scalar_to_message(vec![bls_scalars[0].bls_scalar.clone()]);  
    let messages = PoseidonCipher::generates_messages(bls_scalars);
    let nonce = PoseidonCipher::gen_nonce();

    let y = vdf.calculate_y(&hex::decode(&data.x).unwrap(), data.t).expect("Iterations should have been valiated earlier").try_into().expect("Slice with incorrect length");
    let secret_key = PoseidonCipher::get_secret_key(y);

    let mut cipher_hexes = Vec::new();

    for (_i, message) in messages.iter().enumerate() {
      let cipher = PoseidonCipher::encrypt(&*message, &secret_key, &nonce);
      let cipher_bytes = cipher.to_bytes();
      cipher_hexes.push(hex::encode(cipher_bytes));
    }

    let mut result = Vec::new();
    for (_i, cipher_hex) in cipher_hexes.iter().enumerate() {
    //   println!("cipher_hex: {:?}", &cipher_hex);
    //   println!("secret_key: {:?}", &secret_key);
    //   println!("nonce: {:?}", &nonce);
      let restored_cipher = PoseidonCipher::from_bytes(&hex::decode(cipher_hex).unwrap().try_into().unwrap()).unwrap();

      let decrypt = restored_cipher.decrypt(&secret_key, &nonce);
      result.extend_from_slice(&decrypt.unwrap()); 
    }

    let mut message = PoseidonCipher::convert_bls_scalar_to_message(result);
    message.resize(message_length, 0);
    let result = str::from_utf8(&message[..]).unwrap();

    println!("{{\"message_length\": {}, \"nonce\": {:?}, \"x\": {:?}, \"t\": {:?}, \"cipher_text\": {:?}}}", message_length, hex::encode(nonce.to_bytes()), data.x, data.t, cipher_hexes);
  } else if action_type == "decrypt" {
    let y = vdf.calculate_y(&hex::decode(data.x).unwrap(), data.t).expect("Iterations should have been valiated earlier").try_into().expect("Slice with incorrect length");
    let secret_key = PoseidonCipher::get_secret_key(y);
    let mut result = Vec::new();
    
    let nonce: [u8; 32] = hex::decode(data.nonce).unwrap().try_into().expect("Slice with incorrect length");
    let nonce = PoseidonCipher::convert_nonce(&nonce);
    for (_i, cipher_hex) in data.cipher_text.iter().enumerate() {
    //   println!("cipher_hex: {:?}", &cipher_hex);
    //   println!("secret_key: {:?}", &secret_key);
    //   println!("nonce: {:?}", &nonce);
      let restored_cipher = PoseidonCipher::from_bytes(&hex::decode(cipher_hex).unwrap().try_into().unwrap()).unwrap();

      let decrypt = restored_cipher.decrypt(&secret_key, &nonce);
      result.extend_from_slice(&decrypt.unwrap()); 
    }

    let mut message = PoseidonCipher::convert_bls_scalar_to_message(result);
    message.resize(data.message_length, 0);
    let result = str::from_utf8(&message[..]).unwrap();
    println!("result: {:?}", &result);
  }
}