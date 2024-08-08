use std::str::FromStr;

use num_bigint::BigUint;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{GENERATOR, MAX_SEQUENCER_NUMBER, PRIME_P, PRIME_Q};

use super::{
    big_mul_mod, big_pow_mod, calculate_challenge, generate_random_biguint, generate_uv_pair,
    pow_mod, ExtractionKey, KeyProof, SingleKeyDelayEncryptionParam,
};

pub fn setup(t: u32) -> SingleKeyDelayEncryptionParam {
    let p = BigUint::from_str(PRIME_P).expect("Invalid PRIME_P");
    let q = BigUint::from_str(PRIME_Q).expect("Invalid PRIME_Q");
    let g = BigUint::from_str(GENERATOR).expect("Invalid GENERATOR");

    let n = p * q;

    let h = pow_mod(&g, t, &n);

    SingleKeyDelayEncryptionParam { n, g, t, h }
}

pub fn key_generation_with_proof(
    skde_params: SingleKeyDelayEncryptionParam,
) -> (ExtractionKey, KeyProof) {
    let two_big: BigUint = BigUint::from(2u32);

    let n_half: BigUint = &skde_params.n / two_big;
    let n_half_over_m: BigUint = &n_half / MAX_SEQUENCER_NUMBER;

    let r = generate_random_biguint(n_half_over_m.bits());
    let s = generate_random_biguint(n_half_over_m.bits());
    let k = generate_random_biguint(n_half.bits());

    let uv_pair = generate_uv_pair(&(&r + &s), &s, &skde_params);
    let yw_pair = generate_uv_pair(&k, &r, &skde_params);

    // proof generation for validity for the key pairs

    // TODO: Range proof generation using SNARK
    let key_proof = prove_key_validity(&skde_params, &r, &s, &k);

    (
        ExtractionKey {
            u: uv_pair.u,
            v: uv_pair.v,
            y: yw_pair.u,
            w: yw_pair.v,
        },
        key_proof,
    )
}

fn prove_key_validity(
    skde_params: &SingleKeyDelayEncryptionParam,
    r: &BigUint,
    s: &BigUint,
    k: &BigUint,
) -> KeyProof {
    let m = MAX_SEQUENCER_NUMBER;
    let two_big = BigUint::from(2u32);
    let t = BigUint::from(skde_params.t);
    let n_half = &skde_params.n / &two_big;
    let n_half_plus_n_over_m = &n_half + (&skde_params.n / m);

    let x = generate_random_biguint(n_half_plus_n_over_m.bits());
    let l = generate_random_biguint(n_half.bits());

    let ab_pair = generate_uv_pair(&x, &l, skde_params);
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

    KeyProof {
        a,
        b,
        tau,
        alpha,
        beta,
    }
}

pub fn verify_key_validity(
    skde_params: &SingleKeyDelayEncryptionParam,
    extraction_key: ExtractionKey,
    key_proof: KeyProof,
) -> bool {
    let t = BigUint::from(skde_params.t);
    let n_square: BigUint = &skde_params.n * &skde_params.n;
    let one_big = BigUint::from(1u32);

    let a = key_proof.a;
    let b = key_proof.b;
    let tau = key_proof.tau;
    let alpha = key_proof.alpha;
    let beta = key_proof.beta;

    let u = &extraction_key.u;
    let v = &extraction_key.v;
    let y = &extraction_key.y;
    let w = &extraction_key.w;

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
