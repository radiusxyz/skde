mod partial_key_validity;
mod types;

use big_integer::{big_pow_mod, generate_random_biguint, BigIntChip, BigIntInstructions};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;
use num_bigint::BigUint;
use num_traits::One;
pub use partial_key_validity::*;
pub use types::*;

use crate::SkdeParams;

pub fn generate_partial_key(skde_params: &SkdeParams) -> (SecretValue, PartialKey) {
    let two_big: BigUint = BigUint::from(2u32);

    let n_half: BigUint = &skde_params.n / two_big;
    let n_half_over_m: BigUint = &n_half / skde_params.max_sequencer_number.clone();

    let r = generate_random_biguint(&n_half_over_m);
    let s = generate_random_biguint(&n_half_over_m);
    let k = generate_random_biguint(&n_half);

    let uv_pair = generate_uv_pair(skde_params, &(&r + &s), &s);
    let yw_pair = generate_uv_pair(skde_params, &k, &r);

    (
        SecretValue { r, s, k },
        PartialKey {
            u: uv_pair.u,
            v: uv_pair.v,
            y: yw_pair.u,
            w: yw_pair.v,
        },
    )
}

// Input: (a, b, skde_params = (n, g, t, h))
// Output: (u = g^a, v = h^{a * n} * (1 + n)^b)
pub fn generate_uv_pair(skde_params: &SkdeParams, a: &BigUint, b: &BigUint) -> UVPair {
    let n = &skde_params.n;
    let g = &skde_params.g;
    let h = &skde_params.h;

    // let lambda = n.bits() / 2 + 1;
    let n_square = n * n;
    let n_plus_one = n + BigUint::one();

    // U = g^r mod n
    let u = big_pow_mod(g, a, n);

    // h_exp_r = h^r mod n, h_exp_rn = h^(r * n) mod n^2
    let h_exp_a = big_pow_mod(h, a, n);
    let h_exp_an = big_pow_mod(&h_exp_a, n, &n_square);

    // v = (n+1)^s * hrn mod n^2
    let v = (&big_pow_mod(&n_plus_one, b, &n_square) * &h_exp_an) % &n_square;

    UVPair { u, v }
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
