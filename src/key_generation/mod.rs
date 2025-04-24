mod partial_key_validity;
pub mod zk_range_proof;
pub mod sigma_proof;
mod types;

use anyhow::{Context, Result};
use big_integer::{big_pow_mod, generate_random_biguint, BigIntChip, BigIntInstructions};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;
use num_bigint::BigUint;
use num_traits::{Num, One};
pub use partial_key_validity::*;
pub use types::*;

use crate::SkdeParams;

pub fn generate_partial_key(skde_params: &SkdeParams) -> Result<(SecretValue, PartialKey)> {
    let n = BigUint::from_str_radix(&skde_params.n, 10)
        .context(format!("Failed to parse n parameter: {}", skde_params.n))?;
    let max_sequencer_number = BigUint::from_str_radix(&skde_params.max_sequencer_number, 10)
        .context(format!(
            "Failed to parse max_sequencer_number: {}",
            skde_params.max_sequencer_number
        ))?;
    let two_big: BigUint = BigUint::from(2u32);

    let n_half: BigUint = &n / two_big;
    let n_half_over_m: BigUint = &n_half / max_sequencer_number;

    let r = generate_random_biguint(&n_half_over_m);
    let s = generate_random_biguint(&n_half_over_m);
    let k = generate_random_biguint(&n_half);

    let uv_pair = generate_uv_pair(skde_params, &(&r + &s), &s)
        .context("Failed to generate UV pair for partial key")?;
    let yw_pair = generate_uv_pair(skde_params, &k, &r)
        .context("Failed to generate YW pair for partial key")?;

    Ok((
        SecretValue { r, s, k },
        PartialKey {
            u: uv_pair.u,
            v: uv_pair.v,
            y: yw_pair.u,
            w: yw_pair.v,
        },
    ))
}

// Input: (a, b, skde_params = (n, g, t, h))
// Output: (u = g^a, v = h^{a * n} * (1 + n)^b)
pub fn generate_uv_pair(skde_params: &SkdeParams, a: &BigUint, b: &BigUint) -> Result<UVPair> {
    let n = BigUint::from_str_radix(&skde_params.n, 10)
        .context(format!("Failed to parse n parameter: {}", skde_params.n))?;
    let g = BigUint::from_str_radix(&skde_params.g, 10)
        .context(format!("Failed to parse g parameter: {}", skde_params.g))?;
    let h = BigUint::from_str_radix(&skde_params.h, 10)
        .context(format!("Failed to parse h parameter: {}", skde_params.h))?;

    let n_square = &n * &n;
    let n_plus_one = &n + BigUint::one();

    // U = g^r mod n
    let u = big_pow_mod(&g, a, &n);

    // h_exp_r = h^r mod n, h_exp_rn = h^(r * n) mod n^2
    let h_exp_a = big_pow_mod(&h, a, &n);
    let h_exp_an = big_pow_mod(&h_exp_a, &n, &n_square);

    // v = (n+1)^s * hrn mod n^2
    let v = (&big_pow_mod(&n_plus_one, b, &n_square) * &h_exp_an) % &n_square;

    Ok(UVPair { u, v })
}

pub fn assign_partial_key<F: PrimeField>(
    ctx: &mut RegionCtx<'_, F>,
    bigint_chip: BigIntChip<F>,
    bigint_square_chip: BigIntChip<F>,
    unassigned_partial_key: UnassignedPartialKey<F>,
) -> Result<AssignedPartialKey<F>, Error> {
    Ok(AssignedPartialKey::new(
        bigint_chip.assign_integer(ctx, unassigned_partial_key.u)?,
        bigint_square_chip.assign_integer(ctx, unassigned_partial_key.v)?,
        bigint_chip.assign_integer(ctx, unassigned_partial_key.y)?,
        bigint_square_chip.assign_integer(ctx, unassigned_partial_key.w)?,
    ))
}
