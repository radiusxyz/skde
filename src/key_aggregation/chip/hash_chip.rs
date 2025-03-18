use std::marker::PhantomData;

use big_integer::BigIntChip;
use ff::{FromUniformBytes, PrimeField};
use halo2wrong::halo2::plonk::Error;
use hash::HasherChip;
use maingate::{MainGateConfig, RegionCtx};
use poseidon::{
    chip::{FULL_ROUND, PARTIAL_ROUND},
    PoseidonChip, Spec,
};

use crate::key_aggregation::AggregateHashConfig;

/// Chip for [`AggregateWithHashInstructions`].
#[derive(Debug, Clone)]
pub struct KeyAggregationHashChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    config: AggregateHashConfig,

    bit_len: usize,
    limb_width: usize,

    max_sequencer_number: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    KeyAggregationHashChip<F, T, RATE>
{
    pub fn new(
        config: AggregateHashConfig,
        bit_len: usize,
        limb_width: usize,
        max_sequencer_number: usize,
    ) -> Self {
        KeyAggregationHashChip {
            config,
            bit_len,
            limb_width,
            max_sequencer_number,
            _f: PhantomData,
        }
    }

    /// Getter for [`BigIntChip`].
    pub fn bigint_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_config.clone(),
            self.bit_len,
            self.limb_width,
        )
    }

    /// Getter for [`BigIntSquareChip`].
    pub fn bigint_square_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_square_config.clone(),
            self.bit_len * 2,
            self.limb_width,
        )
    }

    pub fn compute_range_lens(limb_width: usize, limb_count: usize) -> (Vec<usize>, Vec<usize>) {
        let (mut composition_bit_lens, overflow_bit_lens) =
            BigIntChip::<F>::compute_range_lens(limb_width, limb_count);

        composition_bit_lens.push(32 / BigIntChip::<F>::NUM_LOOKUP_LIMBS);

        (composition_bit_lens, overflow_bit_lens)
    }

    pub fn max_sequencer_number(&self) -> usize {
        self.max_sequencer_number
    }

    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<HasherChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let poseidon_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(
            ctx,
            spec,
            main_gate_config,
        )?;

        Ok(HasherChip { poseidon_chip })
    }
}
