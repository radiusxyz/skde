use crate::{
    key_aggregation::{
        AggregateInstructions, AggregateRawConfig, AssignedExtractionKey,
        AssignedKeyAggregationPublicParams, UnassignedKeyAggregationPublicParams,
    },
    key_generation::{AssignedPartialKey, UnassignedPartialKey},
    MAX_SEQUENCER_NUMBER,
};
use big_integer::{BigIntChip, BigIntInstructions};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct AggregateRawChip<F: PrimeField> {
    config: AggregateRawConfig,
    bit_len: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField> AggregateInstructions<F> for AggregateRawChip<F> {
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

impl<F: PrimeField> AggregateRawChip<F> {
    pub const LIMB_WIDTH: usize = 64;

    pub fn new(config: AggregateRawConfig, bit_len: usize) -> Self {
        AggregateRawChip {
            config,
            bit_len,
            _f: PhantomData,
        }
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

#[cfg(test)]
mod test {

    use crate::key_aggregation::AggregateRawCircuit;
    use crate::key_generation::DecomposedPartialKey;
    use crate::{key_aggregation::PartialKey, BIT_COUNT, LIMB_WIDTH};

    use super::*;

    use ff::FromUniformBytes;
    use maingate::mock_prover_verify;
    use num_bigint::BigUint;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_aggregate_key_circuit() {
        fn run<F: FromUniformBytes<64> + Ord>() {
            let mut rng = thread_rng();

            let bit_len = BIT_COUNT as u64;
            let limb_width = LIMB_WIDTH;
            let limb_count = BIT_COUNT / limb_width;

            let mut n = BigUint::default();
            while n.bits() != bit_len {
                n = rng.sample(RandomBits::new(bit_len));
            }
            let n_square = &n * &n;

            let mut partial_keys = vec![];

            let mut aggregated_key = PartialKey {
                u: BigUint::from(1usize),
                v: BigUint::from(1usize),
                y: BigUint::from(1usize),
                w: BigUint::from(1usize),
            };

            for _ in 0..MAX_SEQUENCER_NUMBER {
                let u = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
                let v = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) % &n_square;
                let y = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
                let w = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) % &n_square;

                partial_keys.push(PartialKey {
                    u: u.clone(),
                    v: v.clone(),
                    y: y.clone(),
                    w: w.clone(),
                });

                aggregated_key.u = aggregated_key.u * &u % &n;
                aggregated_key.v = aggregated_key.v * &v % &n_square;
                aggregated_key.y = aggregated_key.y * &y % &n;
                aggregated_key.w = aggregated_key.w * &w % &n_square;
            }

            let combined_partial_limbs: Vec<F> = PartialKey::decompose_and_combine_all_partial_keys(
                partial_keys.clone(),
                limb_width,
                limb_count,
            );

            let decomposed_extraction_key: DecomposedPartialKey<F> =
                PartialKey::decompose_partial_key(&aggregated_key, limb_width, limb_count);
            let mut combined_limbs = decomposed_extraction_key.combine_limbs();

            let circuit = AggregateRawCircuit::<F> {
                partial_key_list: partial_keys,
                aggregated_key,
                n,
                n_square,
                _f: PhantomData,
            };

            combined_limbs.extend(combined_partial_limbs);

            let public_inputs = vec![combined_limbs];
            mock_prover_verify(&circuit, public_inputs);
        }

        use halo2wrong::curves::bn256::Fq as BnFq;

        run::<BnFq>();
    }
}
