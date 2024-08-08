use crate::aggregate::{
    AggregateHashConfig, AggregateInstructions, AssignedAggregatePartialKeys,
    AssignedAggregatePublicParams, AssignedExtractionKey, UnassignedAggregatePublicParams,
    UnassignedExtractionKey, MAX_SEQUENCER_NUMBER,
};
use big_integer::{BigIntChip, BigIntConfig, BigIntInstructions};
use ff::{FromUniformBytes, PrimeField};
use halo2wrong::halo2::plonk::Error;
use hash::HasherChip;
use maingate::{MainGate, MainGateConfig, RangeChip, RegionCtx};
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
    bits_len: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateInstructions<F> for AggregateHashChip<F, T, RATE>
{
    /// Assigns a [`AssignedAggregateWithHashPublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `extraction_key` - an extraction key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregateWithHashPublicKey`].
    fn assign_extraction_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        extraction_key: UnassignedExtractionKey<F>,
    ) -> Result<AssignedExtractionKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip: BigIntChip<F> = self.bigint_square_chip();

        let u = bigint_chip.assign_integer(ctx, extraction_key.u)?;
        let v = bigint_square_chip.assign_integer(ctx, extraction_key.v)?;
        let y = bigint_chip.assign_integer(ctx, extraction_key.y)?;
        let w = bigint_square_chip.assign_integer(ctx, extraction_key.w)?;
        Ok(AssignedExtractionKey::new(u, v, y, w))
    }

    /// Assigns a [`AssignedAggregateWithHashPublicParams`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_params` - public parameters to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregateWithHashPublicParams`].
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: UnassignedAggregatePublicParams<F>,
    ) -> Result<AssignedAggregatePublicParams<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();
        let n = bigint_chip.assign_integer(ctx, public_params.n)?;
        let n_square = bigint_square_chip.assign_integer(ctx, public_params.n_square)?;
        Ok(AssignedAggregatePublicParams { n, n_square })
    }

    /// Given partial keys `Vec<(u,v,y,w)>`, a AggregateWithHash extraction key (u,v,y,w), performs the modular multiplication repeatedly.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `partial_keys` - a vector of input partial keys.
    /// * `public_params` - an assigned AggregateWithHash public params.
    ///
    /// # Return values
    /// Returns an aggregated key for output as [`AssignedExtractionKey<F>`].
    fn aggregate(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        partial_keys: &AssignedAggregatePartialKeys<F>,
        public_params: &AssignedAggregatePublicParams<F>,
    ) -> Result<AssignedExtractionKey<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();
        for each_key in partial_keys.partial_keys.iter() {
            bigint_chip.assert_in_field(ctx, &each_key.u, &public_params.n)?;
            bigint_square_chip.assert_in_field(ctx, &each_key.v, &public_params.n_square)?;
            bigint_chip.assert_in_field(ctx, &each_key.y, &public_params.n)?;
            bigint_square_chip.assert_in_field(ctx, &each_key.w, &public_params.n_square)?;
        }
        let mut u = partial_keys.partial_keys[0].u.clone();
        let mut v = partial_keys.partial_keys[0].v.clone();
        let mut y = partial_keys.partial_keys[0].y.clone();
        let mut w = partial_keys.partial_keys[0].w.clone();

        for i in 1..MAX_SEQUENCER_NUMBER {
            u = bigint_chip.mul_mod(ctx, &u, &partial_keys.partial_keys[i].u, &public_params.n)?;
            v = bigint_square_chip.mul_mod(
                ctx,
                &v,
                &partial_keys.partial_keys[i].v,
                &public_params.n_square,
            )?;
            y = bigint_chip.mul_mod(ctx, &y, &partial_keys.partial_keys[i].y, &public_params.n)?;
            w = bigint_square_chip.mul_mod(
                ctx,
                &w,
                &partial_keys.partial_keys[i].w,
                &public_params.n_square,
            )?;
        }

        Ok(AssignedExtractionKey::new(u, v, y, w))
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateHashChip<F, T, RATE>
{
    pub const LIMB_WIDTH: usize = 64;

    /// Create a new [`AggregateHashChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`AggregateHashChip`].
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
    ///
    /// # Return values
    /// Returns a new [`AggregateHashChip`]
    pub fn new(config: AggregateHashConfig, bits_len: usize) -> Self {
        AggregateHashChip {
            config,
            bits_len,
            _f: PhantomData,
        }
    }

    pub fn new_bigint(config: BigIntConfig, bits_len: usize) -> BigIntChip<F> {
        BigIntChip::<F>::new(config, Self::LIMB_WIDTH, bits_len)
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
            self.bits_len,
        )
    }

    /// Getter for [`BigIntSquareChip`].
    pub fn bigint_square_chip(&self) -> BigIntChip<F> {
        BigIntChip::<F>::new(
            self.config.bigint_square_config.clone(),
            Self::LIMB_WIDTH,
            self.bits_len * 2,
        )
    }

    /// Getter for [`RangeChip`].
    pub fn range_chip(&self) -> RangeChip<F> {
        self.bigint_chip().range_chip()
    }

    /// Getter for [`MainGate`].
    pub fn main_gate(&self) -> MainGate<F> {
        self.bigint_chip().main_gate()
    }

    /// Getter for [`RangeChip`].
    pub fn square_range_chip(&self) -> RangeChip<F> {
        self.bigint_square_chip().range_chip()
    }

    /// Getter for [`MainGate`].
    pub fn square_main_gate(&self) -> MainGate<F> {
        self.bigint_square_chip().main_gate()
    }

    /// Returns the bit length parameters necessary to configure the [`RangeChip`].
    ///
    /// # Arguments
    /// * num_limbs - the default number of limbs of [`Fresh`] integers.
    ///
    /// # Return values
    /// Returns a vector of composition bit lengthes (`composition_bit_lens`) and a vector of overflow bit lengthes (`overflow_bit_lens`), which are necessary for [`RangeConfig`].
    pub fn compute_range_lens(num_limbs: usize) -> (Vec<usize>, Vec<usize>) {
        let (mut composition_bit_lens, overflow_bit_lens) =
            BigIntChip::<F>::compute_range_lens(Self::LIMB_WIDTH, num_limbs);
        composition_bit_lens.push(32 / BigIntChip::<F>::NUM_LOOKUP_LIMBS);
        (composition_bit_lens, overflow_bit_lens)
    }
}
