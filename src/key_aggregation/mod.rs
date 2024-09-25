mod chip;
mod circuit;
mod config;
mod types;

use big_integer::{BigIntChip, BigIntInstructions, UnassignedInteger, *};
pub use chip::*;
pub use circuit::*;
pub use config::*;
use ff::PrimeField;
use halo2wrong::halo2::{circuit::Value, plonk::Error};
use maingate::RegionCtx;
use num_bigint::BigUint;
use num_traits::One;
pub use types::*;

use crate::{key_generation::PartialKey, SkdeParams};

/// Public Parameters that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedKeyAggregationPublicParams<F: PrimeField> {
    pub n: UnassignedInteger<F>,
    pub n_square: UnassignedInteger<F>,
}

impl<F: PrimeField> UnassignedKeyAggregationPublicParams<F> {
    pub fn without_witness(num_limbs: usize) -> Self {
        Self {
            n: UnassignedInteger::new(Value::unknown(), num_limbs),
            n_square: UnassignedInteger::new(Value::unknown(), num_limbs * 2),
        }
    }
}

/// Assigned AggregateWithHash public params.
#[derive(Clone, Debug)]
pub struct AssignedKeyAggregationPublicParams<F: PrimeField> {
    pub n: AssignedInteger<F, Fresh>,
    pub n_square: AssignedInteger<F, Fresh>,
}

pub fn assign_public_params<F: PrimeField>(
    ctx: &mut RegionCtx<'_, F>,
    bigint_chip: BigIntChip<F>,
    bigint_square_chip: BigIntChip<F>,
    public_params: UnassignedKeyAggregationPublicParams<F>,
) -> Result<AssignedKeyAggregationPublicParams<F>, Error> {
    Ok(AssignedKeyAggregationPublicParams {
        n: bigint_chip.assign_integer(ctx, public_params.n)?,
        n_square: bigint_square_chip.assign_integer(ctx, public_params.n_square)?,
    })
}

pub fn aggregate_key(
    skde_params: &SkdeParams,
    partial_key_list: &Vec<PartialKey>,
) -> AggregatedKey {
    let n_square = &skde_params.n * &skde_params.n;

    let mut aggregated_u = BigUint::one();
    let mut aggregated_v = BigUint::one();
    let mut aggregated_y = BigUint::one();
    let mut aggregated_w = BigUint::one();

    // Multiply each component of each PartialKey in the array
    for partial_key in partial_key_list {
        aggregated_u = big_mul_mod(&aggregated_u, &partial_key.u, &skde_params.n);
        aggregated_v = big_mul_mod(&aggregated_v, &partial_key.v, &n_square);
        aggregated_y = big_mul_mod(&aggregated_y, &partial_key.y, &skde_params.n);
        aggregated_w = big_mul_mod(&aggregated_w, &partial_key.w, &n_square);
    }

    // Create a new AggregatedKey instance with the calculated results
    AggregatedKey {
        u: aggregated_u,
        v: aggregated_v,
        y: aggregated_y,
        w: aggregated_w,
    }
}

pub fn aggregate_assigned_key<F: PrimeField>(
    ctx: &mut RegionCtx<'_, F>,
    bigint_chip: BigIntChip<F>,
    bigint_square_chip: BigIntChip<F>,
    max_sequencer_number: usize,
    assigned_extraction_key: &AssignedExtractionKey<F>,
    public_params: &AssignedKeyAggregationPublicParams<F>,
) -> Result<AssignedAggregatedKey<F>, Error> {
    for each_key in assigned_extraction_key.partial_key_list.iter() {
        bigint_chip.assert_in_field(ctx, &each_key.u, &public_params.n)?;
        bigint_square_chip.assert_in_field(ctx, &each_key.v, &public_params.n_square)?;
        bigint_chip.assert_in_field(ctx, &each_key.y, &public_params.n)?;
        bigint_square_chip.assert_in_field(ctx, &each_key.w, &public_params.n_square)?;
    }

    let mut u = assigned_extraction_key.partial_key_list[0].u.clone();
    let mut v = assigned_extraction_key.partial_key_list[0].v.clone();
    let mut y = assigned_extraction_key.partial_key_list[0].y.clone();
    let mut w = assigned_extraction_key.partial_key_list[0].w.clone();

    for i in 1..max_sequencer_number {
        u = bigint_chip.mul_mod(
            ctx,
            &u,
            &assigned_extraction_key.partial_key_list[i].u,
            &public_params.n,
        )?;
        v = bigint_square_chip.mul_mod(
            ctx,
            &v,
            &assigned_extraction_key.partial_key_list[i].v,
            &public_params.n_square,
        )?;
        y = bigint_chip.mul_mod(
            ctx,
            &y,
            &assigned_extraction_key.partial_key_list[i].y,
            &public_params.n,
        )?;
        w = bigint_square_chip.mul_mod(
            ctx,
            &w,
            &assigned_extraction_key.partial_key_list[i].w,
            &public_params.n_square,
        )?;
    }

    Ok(AssignedAggregatedKey::new(u, v, y, w))
}
