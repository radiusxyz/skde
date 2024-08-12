use big_integer::{big_mul_mod, big_pow_mod, generate_random_biguint};
use num_bigint::BigUint;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{SkdeParams, MAX_SEQUENCER_NUMBER};

use super::{
    generate_uv_pair,
    types::{PartialKey, SecretValue},
};

#[derive(Debug, Clone)]
pub struct UVPair {
    pub u: BigUint,
    pub v: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialKeyProof {
    pub a: BigUint,
    pub b: BigUint,
    pub tau: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

pub fn prove_partial_key_validity(
    skde_params: &SkdeParams,
    secret_value: &SecretValue,
) -> PartialKeyProof {
    let r = &secret_value.r;
    let s = &secret_value.s;
    let k = &secret_value.k;
    let t = BigUint::from(skde_params.t);

    let two_big = BigUint::from(2u32);

    let n_half = &skde_params.n / &two_big;
    let n_half_plus_n_over_m = &n_half + (&skde_params.n / MAX_SEQUENCER_NUMBER);

    let l = generate_random_biguint(n_half.bits());
    let x = generate_random_biguint(n_half_plus_n_over_m.bits());

    let ab_pair = generate_uv_pair(skde_params, &x, &l);

    let a = ab_pair.u;
    let b = ab_pair.v;

    let tau = big_pow_mod(&skde_params.g, &l, &skde_params.n);

    // Calculate SHA-512 hash
    let transcript = vec![
        &skde_params.n,
        &skde_params.g,
        &t,
        &skde_params.h,
        &a,
        &b,
        &tau,
    ];

    let e = calculate_challenge(&transcript);

    let alpha = (r + s + k) * &e + &x;
    let beta = (r + s) * &e + &l;

    PartialKeyProof {
        a,
        b,
        tau,
        alpha,
        beta,
    }
}

pub fn verify_partial_key_validity(
    skde_params: &SkdeParams,
    partial_key: PartialKey,
    partial_key_proof: PartialKeyProof,
) -> bool {
    let t = BigUint::from(skde_params.t);
    let n_square: BigUint = &skde_params.n * &skde_params.n;
    let one_big = BigUint::from(1u32);

    let a = partial_key_proof.a;
    let b = partial_key_proof.b;
    let tau = partial_key_proof.tau;
    let alpha = partial_key_proof.alpha;
    let beta = partial_key_proof.beta;

    let u = &partial_key.u;
    let v = &partial_key.v;
    let y = &partial_key.y;
    let w = &partial_key.w;

    // Calculate SHA-512 hash for the challenge
    let transcript = vec![
        &skde_params.n,
        &skde_params.g,
        &t,
        &skde_params.h,
        &a,
        &b,
        &tau,
    ];
    let e = calculate_challenge(&transcript);

    let h_exp_nalpha = big_pow_mod(&skde_params.h, &(&alpha * &skde_params.n), &n_square);
    let n_plus_one_exp_beta = big_pow_mod(&(&skde_params.n + &one_big), &beta, &n_square);

    let uy = big_mul_mod(u, y, &skde_params.n);
    let vw = big_mul_mod(v, w, &n_square);

    // Parallel computation of lhs and rhs vectors
    let (lhs, rhs): (Vec<BigUint>, Vec<BigUint>) = rayon::join(
        || {
            vec![
                big_pow_mod(&skde_params.g, &alpha, &skde_params.n),
                big_mul_mod(&h_exp_nalpha, &n_plus_one_exp_beta, &n_square),
                big_pow_mod(&skde_params.g, &beta, &skde_params.n),
            ]
        },
        || {
            vec![
                big_mul_mod(&big_pow_mod(&uy, &e, &skde_params.n), &a, &skde_params.n),
                big_mul_mod(&big_pow_mod(&vw, &e, &n_square), &b, &n_square),
                big_mul_mod(&big_pow_mod(u, &e, &skde_params.n), &tau, &skde_params.n),
            ]
        },
    );

    // Parallel verification of lhs and rhs vectors
    lhs.par_iter().zip(rhs.par_iter()).all(|(l, r)| l == r)
}

pub fn calculate_challenge(values: &[&BigUint]) -> BigUint {
    let mut sha = Sha512::new();

    for value in values {
        sha.update(&value.to_bytes_be());
    }

    let hash = sha.finalize();

    BigUint::from_bytes_be(&hash)
}
