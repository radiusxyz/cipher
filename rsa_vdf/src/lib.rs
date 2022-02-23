#![allow(non_snake_case)]

use crate::utilities::ErrorReason;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::arithmetic::{traits::*, BigInt};
use serde::{Deserialize, Serialize};
use utilities::{compute_rsa_modulus, h_g, hash_to_prime};

const BIT_LENGTH: usize = 2048;
const SEED_LENGTH: usize = 256;
pub mod utilities;

pub struct ElGamal;
pub struct ExponentElGamal;

/// Wesolowski VDF, based on https://eprint.iacr.org/2018/712.pdf.
/// Original paper: https://eprint.iacr.org/2018/623.pdf
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SolvedVDF {
  vdf_instance: UnsolvedVDF,
  pub y: BigInt,
  pub pi: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetupForVDF {
  pub t: BigInt,
  pub n: BigInt,
  pub pi_n: BigInt,
  pub p: BigInt,
  pub q: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnsolvedVDF {
  pub x: BigInt,
  pub setup: SetupForVDF,
}

impl SetupForVDF {
  pub fn public_setup(t: &BigInt) -> Self {
    // todo: setup can also be used to define H_G. for example pick random domain separator
    let (p, q, n) = compute_rsa_modulus(BIT_LENGTH);
    let pi_n = &p.sub(&BigInt::one()).mul(&q.sub(&BigInt::one()));
    SetupForVDF {
      t: t.clone(),
      n,
      p,
      q,
      pi_n: pi_n.clone(),
    }
  }

  pub fn get_rsa_modulus() -> (BigInt, BigInt, BigInt, BigInt) {
    let x = BigInt::sample(SEED_LENGTH);
    let (p, q, n) = compute_rsa_modulus(BIT_LENGTH);
    (x, p, q, n)
  }

  pub fn public_setup2(x: &BigInt, t: &BigInt, p: &BigInt, q: &BigInt) -> UnsolvedVDF {
    let n = p.clone() * q.clone();
    // let n = n - BigInt::one();
    // let n = n.div_floor(&BigInt::from(2));
    let pi_n = &p.sub(&BigInt::one()).mul(&q.sub(&BigInt::one()));

    UnsolvedVDF {
      x: x.clone(),
      setup: SetupForVDF {
        t: t.clone(),
        n,
        p: p.clone(),
        q: q.clone(),
        pi_n: pi_n.clone(),
      },
    }
  }

  pub fn public_setup3(x: &BigInt, t: &BigInt, n: &BigInt) -> UnsolvedVDF {
    UnsolvedVDF {
      x: x.clone(),
      setup: SetupForVDF {
        t: t.clone(),
        n: n.clone(),
        p: BigInt::zero(),
        q: BigInt::zero(),
        pi_n: BigInt::zero(),
      },
    }
  }
}

impl UnsolvedVDF {
  pub fn cal_y(unsolved_vdf: &UnsolvedVDF) -> BigInt {
    let n = unsolved_vdf.setup.n.clone();
    let x = unsolved_vdf.x.clone();
    let t = unsolved_vdf.setup.t.clone();
    let mut loop_count = BigInt::from(1);
    let two = &BigInt::from(2);

    let mut i = BigInt::zero();
    while i < t {
      loop_count = BigInt::mul(&loop_count, &two);
      i = i + BigInt::one();
    }
    // println!("t: {:?}", t);
    // println!("loop_count: {:?}", loop_count);

    let g = h_g(&n, &x);
    let mut y = g.clone();
    let mut i = BigInt::zero();

    while i < loop_count {
      y = BigInt::mod_mul(&y, &g, &n);
      i = i + BigInt::one();
    }
    y
  }

  pub fn cal_y_with_trapdoor(unsolved_vdf: &UnsolvedVDF) -> BigInt {
    let n = unsolved_vdf.setup.n.clone();
    let pi_n = unsolved_vdf.setup.pi_n.clone();
    let x = unsolved_vdf.x.clone();
    let t = unsolved_vdf.setup.t.clone();
    let mut loop_count = BigInt::from(1);
    let two = BigInt::from(2);

    let mut i = BigInt::zero();
    while i < t {
      loop_count = BigInt::mod_mul(&loop_count, &two, &pi_n);
      i = i + BigInt::one();
    }

    let g = h_g(&n, &x);
    let mut y = g.clone();
    let mut i = BigInt::zero();

    // println!("loop_count: {:?}", loop_count);
    while i < loop_count {
      y = BigInt::mod_mul(&y, &g, &n);
      i = i + BigInt::one();
    }
    y
  }

  //algorithm 3 from https://eprint.iacr.org/2018/623.pdf
  pub fn eval(unsolved_vdf: &UnsolvedVDF) -> SolvedVDF {
    let n = unsolved_vdf.setup.n.clone();
    let x = unsolved_vdf.x.clone();
    let t = unsolved_vdf.setup.t.clone();
    // println!("-----------");
    // println!("n: {:?}", n);
    // println!("x: {:?}", x);
    // println!("t: {:?}", t);
    // println!("-----------");

    let g = h_g(&n, &x);
    let y = UnsolvedVDF::cal_y(&unsolved_vdf);
    // let mut y = g.clone();
    // let mut i = BigInt::zero();

    // while i < t {
    //   y = BigInt::mod_mul(&y, &y, &n);
    //   i = i + BigInt::one();
    // }
    let l = hash_to_prime(&unsolved_vdf.setup, &g, &y);

    //algorithm 4 from https://eprint.iacr.org/2018/623.pdf
    // long division TODO: consider alg 5 instead
    let mut i = BigInt::zero();
    let mut b: BigInt;
    let mut r = BigInt::one();
    let mut r2: BigInt;
    let two = BigInt::from(2);
    let mut pi = BigInt::one();
    let mut g_b: BigInt;

    while i < t {
      r2 = &r * &two;
      b = r2.div_floor(&l);
      r = r2.mod_floor(&l);
      g_b = BigInt::mod_pow(&g, &b, &n);
      pi = BigInt::mod_mul(&pi, &pi, &n);
      pi = BigInt::mod_mul(&pi, &g_b, &n);
      i = i + BigInt::one();
    }

    let vdf = SolvedVDF {
      vdf_instance: unsolved_vdf.clone(),
      y,
      pi,
    };
    vdf
  }

  pub fn eval_with_trapdoor(unsolved_vdf: &UnsolvedVDF) -> SolvedVDF {
    let n = unsolved_vdf.setup.n.clone();
    let x = unsolved_vdf.x.clone();
    let t = unsolved_vdf.setup.t.clone();
    // println!("-----------");
    // println!("n: {:?}", n);
    // println!("x: {:?}", x);
    // println!("t: {:?}", t);
    // println!("-----------");

    let g = h_g(&n, &x);
    let y = UnsolvedVDF::cal_y_with_trapdoor(&unsolved_vdf);

    let l = hash_to_prime(&unsolved_vdf.setup, &g, &y);

    //algorithm 4 from https://eprint.iacr.org/2018/623.pdf
    // long division TODO: consider alg 5 instead
    let mut i = BigInt::zero();
    let mut b: BigInt;
    let mut r = BigInt::one();
    let mut r2: BigInt;
    let two = BigInt::from(2);
    let mut pi = BigInt::one();
    let mut g_b: BigInt;

    while i < t {
      r2 = &r * &two;
      b = r2.div_floor(&l);
      r = r2.mod_floor(&l);
      g_b = BigInt::mod_pow(&g, &b, &n);
      pi = BigInt::mod_mul(&pi, &pi, &n);
      pi = BigInt::mod_mul(&pi, &g_b, &n);
      i = i + BigInt::one();
    }

    let vdf = SolvedVDF {
      vdf_instance: unsolved_vdf.clone(),
      y,
      pi,
    };
    vdf
  }
}

impl SolvedVDF {
  //algorithm 2 from https://eprint.iacr.org/2018/623.pdf
  pub fn verify(&self, unsolved_vdf: &UnsolvedVDF) -> Result<(), ErrorReason> {
    // we first check the solution received is for VDF generated by us
    if &self.vdf_instance != unsolved_vdf {
      return Err(ErrorReason::MisMatchedVDF);
    }

    let n = self.vdf_instance.setup.n.clone();
    let g = h_g(&self.vdf_instance.setup.n, &self.vdf_instance.x);

    // test that y is element in the group : https://eprint.iacr.org/2018/712.pdf 2.1 line 0
    if &self.y >= &n || &self.pi >= &n {
      return Err(ErrorReason::VDFVerifyError);
    }

    let l = hash_to_prime(&self.vdf_instance.setup, &g, &self.y);
    let r = BigInt::mod_pow(&BigInt::from(2), &self.vdf_instance.setup.t, &l);
    let pi_l = BigInt::mod_pow(&self.pi, &l, &n);
    let g_r = BigInt::mod_pow(&g, &r, &n);
    let pi_l_g_r = BigInt::mod_mul(&pi_l, &g_r, &n);

    match pi_l_g_r == self.y {
      true => return Ok(()),
      false => return Err(ErrorReason::VDFVerifyError),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::SetupForVDF;
  use super::UnsolvedVDF;
  use curv::arithmetic::traits::Samplable;
  use curv::BigInt;
  use std::time::Instant;

  #[test]
  fn test_vdf_valid_proof() {
    let t = BigInt::sample(13);
    let setup = SetupForVDF::public_setup(&t);

    let mut i = 0;
    while i < 10 {
      let unsolved_vdf = SetupForVDF::pick_challenge(&setup);
      let start = Instant::now();
      let solved_vdf = UnsolvedVDF::eval(&unsolved_vdf);
      let duration1 = start.elapsed();
      let start = Instant::now();
      // here unsolved_vdf is the version that was kept by the challenger
      let res = solved_vdf.verify(&unsolved_vdf);
      let duration2 = start.elapsed();
      i = i + 1;

      // todo: compute mean and std
      println!("eval time: {:?}", duration1);
      println!("verify time: {:?}", duration2);

      assert!(res.is_ok());
    }
  }
}
