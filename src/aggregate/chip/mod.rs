use super::{AggregateConfig, MAX_SEQUENCER_NUMBER};
use crate::{
    AggregateInstructions, AggregatePublicParams, AssignedAggregatePartialKeys,
    AssignedAggregatePublicParams, AssignedExtractionKey, UnassignedExtractionKey,
};
use big_integer::{BigIntChip, BigIntInstructions};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::{MainGate, RangeChip, RegionCtx};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct AggregateChip<F: PrimeField> {
    config: AggregateConfig,
    bits_len: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField> AggregateInstructions<F> for AggregateChip<F> {
    /// Assigns a [`AssignedAggregatePublicKey`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a Aggregate public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregatePublicKey`].
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

    /// Assigns a [`AssignedAggregatePublicParams`].
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `public_key` - a Aggregate public key to assign.
    ///
    /// # Return values
    /// Returns a new [`AssignedAggregatePublicParams`].
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: AggregatePublicParams<F>,
    ) -> Result<AssignedAggregatePublicParams<F>, Error> {
        let bigint_chip = self.bigint_chip();
        let bigint_square_chip = self.bigint_square_chip();
        // let bigint_square_chip = self.bigint_square_chip();
        let n = bigint_chip.assign_integer(ctx, public_params.n)?;
        let n_square = bigint_square_chip.assign_integer(ctx, public_params.n_square)?;
        Ok(AssignedAggregatePublicParams::new(n, n_square))
    }

    /// Given a base `x`, a Aggregate public key (e,n), performs the modular power `x^e mod n`.
    ///
    /// # Arguments
    /// * `ctx` - a region context.
    /// * `partial_keys` - a vector of input partial keys.
    /// * `aggregated_key` - an aggregated key for output.
    /// * `public_params` - an assigned Aggregate public params.
    ///
    /// # Return values
    /// Returns the modular power result `x^e mod n` as [`AssignedInteger<F, Fresh>`].
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

        Ok(AssignedExtractionKey::new(
            u.clone(),
            v.clone(),
            y.clone(),
            w.clone(),
        ))
    }
}

impl<F: PrimeField> AggregateChip<F> {
    pub const LIMB_WIDTH: usize = 64;

    /// Create a new [`AggregateChip`] from the configuration and parameters.
    ///
    /// # Arguments
    /// * config - a configuration for [`AggregateChip`].
    /// * bits_len - the default bit length of [`Fresh`] type integers in this chip.
    /// * exp_limb_bits - the width of each limb when the exponent is decomposed.
    ///
    /// # Return values
    /// Returns a new [`AggregateChip`]
    pub fn new(config: AggregateConfig, bits_len: usize) -> Self {
        AggregateChip {
            config,
            bits_len,
            _f: PhantomData,
        }
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

#[cfg(test)]
mod test {

    use crate::{
        aggregate, apply_aggregate_key_instance_constraints,
        apply_partial_key_instance_constraints, BigIntConfig, DecomposedExtractionKey,
        ExtractionKey, UnassignedInteger, BITS_LEN, LIMB_WIDTH,
    };

    use super::*;
    use ff::FromUniformBytes;
    use halo2wrong::halo2::{
        circuit::{Chip, SimpleFloorPlanner},
        plonk::{Circuit, Column, ConstraintSystem, Instance},
    };
    use maingate::{decompose_big, mock_prover_verify, RangeInstructions};
    use num_bigint::BigUint;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    struct TestAggregateKeyCircuit<F: PrimeField> {
        partial_keys: Vec<ExtractionKey>,
        aggregated_key: ExtractionKey,
        n: BigUint,
        n_square: BigUint,
        _f: PhantomData<F>,
    }

    impl<F: PrimeField> TestAggregateKeyCircuit<F> {
        fn aggregate_chip(&self, config: AggregateConfig) -> AggregateChip<F> {
            AggregateChip::new(config, BITS_LEN)
        }
    }

    impl<F: PrimeField> Circuit<F> for TestAggregateKeyCircuit<F> {
        type Config = AggregateConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);
            let (composition_bit_lens, overflow_bit_lens) =
                AggregateChip::<F>::compute_range_lens(BITS_LEN / LIMB_WIDTH);
            let range_config = RangeChip::<F>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );
            let (square_composition_bit_lens, square_overflow_bit_lens) =
                AggregateChip::<F>::compute_range_lens(BITS_LEN * 2 / LIMB_WIDTH);
            let square_range_config = RangeChip::<F>::configure(
                meta,
                &main_gate_config,
                square_composition_bit_lens,
                square_overflow_bit_lens,
            );
            let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
            let bigint_square_config =
                BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

            Self::Config {
                bigint_config,
                bigint_square_config,
                instance: meta.instance_column(),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
        ) -> Result<(), Error> {
            let instances = config.instance.clone();
            let aggregate_chip = self.aggregate_chip(config);
            let bigint_chip = aggregate_chip.bigint_chip();
            let bigint_square_chip = aggregate_chip.bigint_square_chip();
            let limb_width = LIMB_WIDTH;
            let num_limbs = BITS_LEN / LIMB_WIDTH;
            let (partial_keys_result, valid_agg_key_result) = layouter.assign_region(
                || "aggregate key test with 2048 bits RSA parameter",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let n_limbs = decompose_big::<F>(self.n.clone(), num_limbs, limb_width);
                    let n_unassigned = UnassignedInteger::from(n_limbs);

                    let n_square_limbs =
                        decompose_big::<F>(self.n_square.clone(), num_limbs * 2, limb_width);
                    let n_square_unassigned = UnassignedInteger::from(n_square_limbs);

                    let mut partial_keys_assigned = vec![];
                    for i in 0..MAX_SEQUENCER_NUMBER {
                        let decomposed_partial_key =
                            ExtractionKey::decompose_extraction_key(&self.partial_keys[i]);

                        let (u_unassigned, v_unassigned, y_unassigned, w_unassigned) =
                            decomposed_partial_key.to_unassigned_integers();

                        let extraction_key_unassgined = UnassignedExtractionKey {
                            u: u_unassigned,
                            v: v_unassigned,
                            y: y_unassigned,
                            w: w_unassigned,
                        };
                        partial_keys_assigned.push(
                            aggregate_chip.assign_extraction_key(ctx, extraction_key_unassgined)?,
                        );
                    }
                    let partial_keys = AssignedAggregatePartialKeys {
                        partial_keys: partial_keys_assigned,
                    };

                    let public_params_unassigned = AggregatePublicParams::new(
                        n_unassigned.clone(),
                        n_square_unassigned.clone(),
                    );
                    let public_params =
                        aggregate_chip.assign_public_params(ctx, public_params_unassigned)?;
                    let valid_agg_key = aggregate_chip.aggregate(
                        ctx,
                        &partial_keys.clone(),
                        &public_params.clone(),
                    )?;

                    Ok((partial_keys, valid_agg_key))
                },
            )?;

            apply_aggregate_key_instance_constraints(
                &mut layouter,
                &valid_agg_key_result,
                num_limbs,
                instances,
            )?;

            apply_partial_key_instance_constraints(
                &mut layouter,
                &partial_keys_result,
                num_limbs,
                instances,
            )?;

            let range_chip = bigint_chip.range_chip();
            let range_square_chip = bigint_square_chip.range_chip();
            range_chip.load_table(&mut layouter)?;
            range_square_chip.load_table(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn test_aggregate_key_circuit() {
        fn run<F: FromUniformBytes<64> + Ord>() {
            let mut rng = thread_rng();
            let bits_len = BITS_LEN as u64;
            let mut n = BigUint::default();
            while n.bits() != bits_len {
                n = rng.sample(RandomBits::new(bits_len));
            }
            let n_square = &n * &n;

            let mut partial_keys = vec![];

            let mut aggregated_key = ExtractionKey {
                u: BigUint::from(1usize),
                v: BigUint::from(1usize),
                y: BigUint::from(1usize),
                w: BigUint::from(1usize),
            };

            for _ in 0..MAX_SEQUENCER_NUMBER {
                let u = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                let v = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;
                let y = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
                let w = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;

                partial_keys.push(ExtractionKey {
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

            let combined_partial_limbs: Vec<F> =
                ExtractionKey::decompose_and_combine_all_partial_keys(partial_keys.clone());

            let decomposed_extraction_key: DecomposedExtractionKey<F> =
                ExtractionKey::decompose_extraction_key(&aggregated_key);
            let mut combined_limbs = decomposed_extraction_key.combine_limbs();

            let circuit = TestAggregateKeyCircuit::<F> {
                partial_keys,
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
        // use halo2wrong::curves::pasta::{Fp as PastaFp, Fq as PastaFq};
        run::<BnFq>();
        // run::<PastaFp>();
        // run::<PastaFq>();
    }
}
