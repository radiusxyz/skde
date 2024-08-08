use crate::key_aggregation::{
    AggregateHashConfig, AggregateInstructions, AssignedExtractionKey,
    AssignedKeyAggregationPublicParams, UnassignedKeyAggregationPublicParams,
};
use crate::key_generation::{AssignedPartialKey, UnassignedPartialKey};
use crate::MAX_SEQUENCER_NUMBER;
use big_integer::{BigIntChip, BigIntInstructions};
use ff::{FromUniformBytes, PrimeField};
use halo2wrong::halo2::plonk::Error;
use hash::HasherChip;
use maingate::{MainGateConfig, RegionCtx};
use poseidon::chip::{FULL_ROUND, PARTIAL_ROUND};
use poseidon::{PoseidonChip, Spec};
use std::marker::PhantomData;

/// Chip for [`AggregateWithHashInstructions`].
#[derive(Debug, Clone)]
pub struct AggregateHashChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    config: AggregateHashConfig,
    bit_len: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateInstructions<F> for AggregateHashChip<F, T, RATE>
{
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: UnassignedKeyAggregationPublicParams<F>,
    ) -> Result<AssignedKeyAggregationPublicParams<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();

        Ok(AssignedKeyAggregationPublicParams {
            n: bigint_chip.assign_integer(ctx, public_params.n)?,
            n_square: bigint_square_chip.assign_integer(ctx, public_params.n_square)?,
        })
    }

    fn assign_partial_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned_partial_key: UnassignedPartialKey<F>,
    ) -> Result<AssignedPartialKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip: BigIntChip<F> = self.bigint_square_chip();

        Ok(AssignedPartialKey::new(
            bigint_chip.assign_integer(ctx, unassigned_partial_key.u)?,
            bigint_square_chip.assign_integer(ctx, unassigned_partial_key.v)?,
            bigint_chip.assign_integer(ctx, unassigned_partial_key.y)?,
            bigint_square_chip.assign_integer(ctx, unassigned_partial_key.w)?,
        ))
    }

    fn aggregate_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        assigned_extraction_key: &AssignedExtractionKey<F>,
        public_params: &AssignedKeyAggregationPublicParams<F>,
    ) -> Result<AssignedPartialKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();

        for each_key in assigned_extraction_key.partial_keys.iter() {
            bigint_chip.assert_in_field(ctx, &each_key.u, &public_params.n)?;
            bigint_square_chip.assert_in_field(ctx, &each_key.v, &public_params.n_square)?;
            bigint_chip.assert_in_field(ctx, &each_key.y, &public_params.n)?;
            bigint_square_chip.assert_in_field(ctx, &each_key.w, &public_params.n_square)?;
        }

        let mut u = assigned_extraction_key.partial_keys[0].u.clone();
        let mut v = assigned_extraction_key.partial_keys[0].v.clone();
        let mut y = assigned_extraction_key.partial_keys[0].y.clone();
        let mut w = assigned_extraction_key.partial_keys[0].w.clone();

        for i in 1..MAX_SEQUENCER_NUMBER {
            u = bigint_chip.mul_mod(
                ctx,
                &u,
                &assigned_extraction_key.partial_keys[i].u,
                &public_params.n,
            )?;

            v = bigint_square_chip.mul_mod(
                ctx,
                &v,
                &assigned_extraction_key.partial_keys[i].v,
                &public_params.n_square,
            )?;

            y = bigint_chip.mul_mod(
                ctx,
                &y,
                &assigned_extraction_key.partial_keys[i].y,
                &public_params.n,
            )?;

            w = bigint_square_chip.mul_mod(
                ctx,
                &w,
                &assigned_extraction_key.partial_keys[i].w,
                &public_params.n_square,
            )?;
        }

        Ok(AssignedPartialKey::new(u, v, y, w))
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateHashChip<F, T, RATE>
{
    pub const LIMB_WIDTH: usize = 64;

    pub fn new(config: AggregateHashConfig, bit_len: usize) -> Self {
        AggregateHashChip {
            config,
            bit_len,
            _f: PhantomData,
        }
    }

    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let pos_hash_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(
            ctx,
            spec,
            main_gate_config,
        )?;

        Ok(HasherChip {
            pose_chip: pos_hash_chip,
        })
    }

    /// Getter for [`BigIntChip`].
    pub fn bigint_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_config.clone(),
            Self::LIMB_WIDTH,
            self.bit_len,
        )
    }

    /// Getter for [`BigIntSquareChip`].
    pub fn bigint_square_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_square_config.clone(),
            Self::LIMB_WIDTH,
            self.bit_len * 2,
        )
    }

    pub fn compute_range_lens(num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
        let (mut composition_bit_lens, overflow_bit_lens) =
            BigIntChip::<F>::compute_range_lens(Self::LIMB_WIDTH, num_limbs);

        composition_bit_lens.push(32 / BigIntChip::<F>::NUM_LOOKUP_LIMBS);

        (composition_bit_lens, overflow_bit_lens)
    }
}
