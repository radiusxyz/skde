use std::marker::PhantomData;

use big_integer::BigIntChip;
use ff::PrimeField;

use crate::key_aggregation::AggregateRawConfig;

#[derive(Debug, Clone)]
pub struct KeyAggregationRawChip<F: PrimeField> {
    config: AggregateRawConfig,

    bit_len: usize,
    limb_width: usize,

    max_sequencer_number: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField> KeyAggregationRawChip<F> {
    pub fn new(
        config: AggregateRawConfig,
        bit_len: usize,
        limb_width: usize,
        max_sequencer_number: usize,
    ) -> Self {
        KeyAggregationRawChip {
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

    pub fn compute_range_lens(limb_width: usize, limb_count: usize) -> (Vec<usize>, Vec<usize>) {
        let (mut composition_bit_lens, overflow_bit_lens) =
            BigIntChip::<F>::compute_range_lens(limb_width, limb_count);

        composition_bit_lens.push(32 / BigIntChip::<F>::NUM_LOOKUP_LIMBS);

        (composition_bit_lens, overflow_bit_lens)
    }

    /// Getter for [`BigIntSquareChip`].
    pub fn bigint_square_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_square_config.clone(),
            self.bit_len * 2,
            self.limb_width,
        )
    }

    pub fn max_sequencer_number(&self) -> usize {
        self.max_sequencer_number
    }
}
