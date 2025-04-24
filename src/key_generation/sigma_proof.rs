use anyhow::{Context, Result};
use big_integer::{big_mul_mod, big_pow_mod, generate_random_biguint};
use num_bigint::BigUint;
use num_traits::Num;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use super::{
    generate_uv_pair,
    types::{PartialKey, SecretValue},
};
use crate::{SkdeParams, BIT_LEN, MAX_SEQUENCER_NUMBER};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaProof {
    pub a: BigUint,
    pub b: BigUint,
    pub tau: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

/// Generates an non-interactive sigma proof that a given `PartialKey` was
/// correctly constructed from a valid secret (r, s, k) without revealing it.
///
/// # Inputs
/// - `skde_params`: SKDE public parameters
/// - `secret_value`: Secret scalars (r, s, k) used to construct the partial key
///
/// # Returns
/// - `SigmaProof`: A proof that the corresponding (u, v, y, w) values are valid
///
/// # Protocol Summary
/// Constructs (a, b, tau) as commitments to random values (x, l),
/// then computes challenge `e = H(transcript)`, and response values
/// - alpha = (r + s + k) * e + x
/// - beta  = (r + s) * e + l
///
/// These responses are then used in `verify_sigma_proof`
/// to prove knowledge of (r, s, k) consistent with the public key.
pub fn generate_sigma_proof(
    skde_params: &SkdeParams,
    secret_value: &SecretValue,
) -> Result<SigmaProof> {
    let n = BigUint::from_str_radix(&skde_params.n, 10)
        .context(format!("Failed to parse n parameter: {}", skde_params.n))?;
    let g = BigUint::from_str_radix(&skde_params.g, 10)
        .context(format!("Failed to parse g parameter: {}", skde_params.g))?;
    let h = BigUint::from_str_radix(&skde_params.h, 10)
        .context(format!("Failed to parse h parameter: {}", skde_params.h))?;
    let t = BigUint::from(skde_params.t);

    let r = &secret_value.r;
    let s = &secret_value.s;
    let k = &secret_value.k;
    let bit_len_big = BigUint::from(BIT_LEN);

    let two_big = BigUint::from(2u32);
    let twice_bit_len_big = &two_big * bit_len_big;
    let two_big_pow = &big_pow_mod(&two_big, &twice_bit_len_big, &n);

    let n_half = &n / &two_big;
    let n_over_m = &n / MAX_SEQUENCER_NUMBER;
    let n_half_plus_n_over_m = &n_half + &n_over_m;

    let l_range: BigUint = n_over_m * two_big_pow;
    let x_range: BigUint = n_half_plus_n_over_m * two_big_pow;

    let l = generate_random_biguint(&l_range);
    let x = generate_random_biguint(&x_range);

    let ab_pair = generate_uv_pair(skde_params, &x, &l)
        .context("Failed to generate AB pair for partial key proof")?;

    let a = ab_pair.u;
    let b = ab_pair.v;

    let tau = big_pow_mod(&g, &l, &n);

    // Calculate SHA-512 hash
    let transcript = vec![&n, &g, &t, &h, &a, &b, &tau];

    let e = calculate_challenge(&transcript);

    let alpha = (r + s + k) * &e + &x;
    let beta = (r + s) * &e + &l;

    Ok(SigmaProof {
        a,
        b,
        tau,
        alpha,
        beta,
    })
}

/// Verifies a sigma proof of correctness for a `PartialKey` exponent relation
///
/// # Inputs
/// - `skde_params`: SKDE public parameters
/// - `partial_key`: (u, v, y, w) public values
/// - `partial_key_proof`: Proof struct containing (a, b, tau, alpha, beta)
///
/// # Returns
/// - `true` if the proof is valid
/// - `false` if the proof is invalid
///
/// # Verification Equations
/// - g^alpha = (u * y)^e * a mod n
/// - h^{n * alpha} * (n+1)^beta = (v * w)^e * b mod n^2
/// - g^beta = u^e * tau mod n
///
/// These equations are evaluated in parallel and compared.
pub fn verify_sigma_proof(
    skde_params: &SkdeParams,
    partial_key: &PartialKey,
    partial_key_proof: &SigmaProof,
) -> Result<bool> {
    let n = BigUint::from_str_radix(&skde_params.n, 10)
        .context(format!("Failed to parse n parameter: {}", skde_params.n))?;
    let g = BigUint::from_str_radix(&skde_params.g, 10)
        .context(format!("Failed to parse g parameter: {}", skde_params.g))?;
    let h = BigUint::from_str_radix(&skde_params.h, 10)
        .context(format!("Failed to parse h parameter: {}", skde_params.h))?;
    let n_square: BigUint = &n * &n;

    let t = BigUint::from(skde_params.t);
    let one_big = BigUint::from(1u32);

    let a = &partial_key_proof.a;
    let b = &partial_key_proof.b;
    let tau = &partial_key_proof.tau;
    let alpha = &partial_key_proof.alpha;
    let beta = &partial_key_proof.beta;

    let u = &partial_key.u;
    let v = &partial_key.v;
    let y = &partial_key.y;
    let w = &partial_key.w;

    // Calculate SHA-512 hash for the challenge
    let transcript = vec![&n, &g, &t, &h, &a, &b, &tau];
    let e = calculate_challenge(&transcript);

    let h_exp_nalpha = big_pow_mod(&h, &(alpha * n.clone()), &n_square);
    let n_plus_one_exp_beta = big_pow_mod(&(n.clone() + one_big), beta, &n_square);

    let uy = big_mul_mod(u, y, &n.clone());
    let vw = big_mul_mod(v, w, &n_square);

    // Parallel computation of lhs and rhs vectors
    let (lhs, rhs): (Vec<BigUint>, Vec<BigUint>) = rayon::join(
        || {
            vec![
                big_pow_mod(&g, alpha, &n),
                big_mul_mod(&h_exp_nalpha, &n_plus_one_exp_beta, &n_square),
                big_pow_mod(&g, beta, &n),
            ]
        },
        || {
            vec![
                big_mul_mod(&big_pow_mod(&uy, &e, &n), a, &n),
                big_mul_mod(&big_pow_mod(&vw, &e, &n_square), b, &n_square),
                big_mul_mod(&big_pow_mod(u, &e, &n), tau, &n),
            ]
        },
    );

    // Parallel verification of lhs and rhs vectors
    let valid = lhs.par_iter().zip(rhs.par_iter()).all(|(l, r)| l == r);

    if !valid {
        Err(anyhow::anyhow!("Partial key verification failed"))
    } else {
        Ok(valid)
    }
}

/// Computes a Fiat-Shamir challenge `e` using SHA-512 over a vector of BigUints
///
/// # Inputs
/// - `values`: A slice of BigUint references representing the protocol
///   transcript
///
/// # Returns
/// - A `BigUint` challenge value derived from the transcript
///
/// # Notes
/// - This function implements Fiat-Shamir transformation for non-interactive
///   proofs
/// - The resulting hash is interpreted as a BigUint in big-endian form
pub fn calculate_challenge(values: &[&BigUint]) -> BigUint {
    let mut sha = Sha512::new();

    for value in values {
        sha.update(value.to_bytes_be());
    }

    let hash = sha.finalize();

    BigUint::from_bytes_be(&hash)
}
