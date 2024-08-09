use crate::{
    key_aggregation::{
        aggregate_assigned_key, assign_public_params, AggregateRawConfig, AggregatedKey,
        AssignedAggregatedKey, AssignedExtractionKey, KeyAggregationRawChip, PartialKey,
        UnassignedKeyAggregationPublicParams,
    },
    key_generation::{assign_partial_key, UnassignedPartialKey},
    BIT_LEN, LIMB_WIDTH,
};
use big_integer::*;
use ff::PrimeField;
use halo2wrong::{
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
    },
    RegionCtx,
};
use maingate::{decompose_big, MainGate, RangeChip, RangeInstructions};
use num_bigint::BigUint;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct AggregateRawCircuit<F: PrimeField> {
    pub n: BigUint,
    pub n_square: BigUint,

    pub partial_key_list: Vec<PartialKey>,
    pub aggregated_key: AggregatedKey,

    pub max_sequencer_count: usize,

    pub _f: PhantomData<F>,
}

impl<F: PrimeField> AggregateRawCircuit<F> {
    pub const BIT_LEN: usize = BIT_LEN;
    pub const LIMB_WIDTH: usize = LIMB_WIDTH;
    pub const LIMB_COUNT: usize = BIT_LEN / LIMB_WIDTH;

    fn key_aggregation_chip(&self, config: AggregateRawConfig) -> KeyAggregationRawChip<F> {
        KeyAggregationRawChip::new(
            config,
            Self::BIT_LEN,
            Self::LIMB_WIDTH,
            self.max_sequencer_count,
        )
    }

    pub fn apply_aggregate_key_instance_constraints(
        &self,
        layouter: &mut impl halo2wrong::halo2::circuit::Layouter<F>,
        aggregated_key: &AssignedAggregatedKey<F>,
        limb_count: usize,
        instance: Column<Instance>,
    ) -> Result<(), Error> {
        // let u_index = 0_usize;
        let v_index = limb_count;
        let y_index = limb_count * 3;
        let w_index = limb_count * 4;

        (0..limb_count).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(aggregated_key.u.limb(i).cell(), instance, i)?;
            layouter.constrain_instance(aggregated_key.y.limb(i).cell(), instance, y_index + i)
        })?;

        (0..limb_count * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(aggregated_key.v.limb(i).cell(), instance, v_index + i)?;
            layouter.constrain_instance(aggregated_key.w.limb(i).cell(), instance, w_index + i)
        })?;
        Ok(())
    }

    pub fn apply_partial_key_instance_constraints(
        &self,
        layouter: &mut impl halo2wrong::halo2::circuit::Layouter<F>,
        assigned_extraction_key: &AssignedExtractionKey<F>,
        limb_count: usize,
        instance: Column<Instance>,
    ) -> Result<(), Error> {
        (0..self.max_sequencer_count).try_for_each(|k| -> Result<(), Error> {
            let u_limb = &assigned_extraction_key.partial_key_list[k].u;
            let v_limb = &assigned_extraction_key.partial_key_list[k].v;
            let y_limb = &assigned_extraction_key.partial_key_list[k].y;
            let w_limb = &assigned_extraction_key.partial_key_list[k].w;

            let base_index = k * 6 * limb_count;
            let u_index = base_index + limb_count * 6;
            let v_index = base_index + limb_count * 7;
            let y_index = base_index + limb_count * 9;
            let w_index = base_index + limb_count * 10;

            (0..limb_count).try_for_each(|i| -> Result<(), Error> {
                layouter.constrain_instance(u_limb.limb(i).cell(), instance, u_index + i)?;
                layouter.constrain_instance(y_limb.limb(i).cell(), instance, y_index + i)
            })?;

            (0..limb_count * 2).try_for_each(|i| -> Result<(), Error> {
                layouter.constrain_instance(v_limb.limb(i).cell(), instance, v_index + i)?;
                layouter.constrain_instance(w_limb.limb(i).cell(), instance, w_index + i)
            })?;

            Ok(())
        })
    }
}

impl<F: PrimeField> Circuit<F> for AggregateRawCircuit<F> {
    type Config = AggregateRawConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);

        let (composition_bit_lens, overflow_bit_lens) =
            KeyAggregationRawChip::<F>::compute_range_lens(Self::LIMB_WIDTH, Self::LIMB_COUNT);
        let (square_composition_bit_lens, square_overflow_bit_lens) =
            KeyAggregationRawChip::<F>::compute_range_lens(Self::LIMB_WIDTH, Self::LIMB_COUNT * 2);

        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        let square_range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            square_composition_bit_lens,
            square_overflow_bit_lens,
        );

        Self::Config {
            bigint_config: BigIntConfig::new(range_config.clone(), main_gate_config.clone()),
            bigint_square_config: BigIntConfig::new(square_range_config, main_gate_config),
            instance: meta.instance_column(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        // TODO: check
        let n_limbs = decompose_big::<F>(self.n.clone(), Self::LIMB_COUNT, Self::LIMB_WIDTH);
        let unassigned_n = UnassignedInteger::from(n_limbs);

        let n_square_limbs = decompose_big::<F>(
            self.n_square.clone(),
            Self::LIMB_COUNT * 2,
            Self::LIMB_WIDTH,
        );
        let unassigned_n_square = UnassignedInteger::from(n_square_limbs);

        let instance = config.instance.clone();
        let key_aggregation_raw_chip = self.key_aggregation_chip(config);

        let (assigned_extraction_key, aggregated_key) = layouter.assign_region(
            || "aggregate key test with 2048 bits RSA parameter",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let mut assigned_partial_key_list = vec![];

                for i in 0..self.max_sequencer_count {
                    let decomposed_partial_key = PartialKey::decompose_partial_key(
                        &self.partial_key_list[i],
                        Self::LIMB_WIDTH,
                        Self::LIMB_COUNT,
                    );

                    let (u_unassigned, v_unassigned, y_unassigned, w_unassigned) =
                        decomposed_partial_key.to_unassigned_integers();
                    let unassigned_partial_key = UnassignedPartialKey {
                        u: u_unassigned,
                        v: v_unassigned,
                        y: y_unassigned,
                        w: w_unassigned,
                    };
                    assigned_partial_key_list.push(assign_partial_key(
                        ctx,
                        key_aggregation_raw_chip.bigint_chip(),
                        key_aggregation_raw_chip.bigint_square_chip(),
                        unassigned_partial_key,
                    )?);
                }

                let assigned_extraction_key = AssignedExtractionKey {
                    partial_key_list: assigned_partial_key_list,
                };

                let unassigned_public_params = UnassignedKeyAggregationPublicParams {
                    n: unassigned_n.clone(),
                    n_square: unassigned_n_square.clone(),
                };
                let assigned_public_params = assign_public_params(
                    ctx,
                    key_aggregation_raw_chip.bigint_chip(),
                    key_aggregation_raw_chip.bigint_square_chip(),
                    unassigned_public_params,
                )?;

                let aggregated_key = aggregate_assigned_key(
                    ctx,
                    key_aggregation_raw_chip.bigint_chip(),
                    key_aggregation_raw_chip.bigint_square_chip(),
                    key_aggregation_raw_chip.max_sequencer_number(),
                    &assigned_extraction_key.clone(),
                    &assigned_public_params.clone(),
                )?;

                Ok((assigned_extraction_key, aggregated_key))
            },
        )?;

        self.apply_aggregate_key_instance_constraints(
            &mut layouter,
            &aggregated_key,
            Self::LIMB_COUNT,
            instance,
        )?;

        self.apply_partial_key_instance_constraints(
            &mut layouter,
            &assigned_extraction_key,
            Self::LIMB_COUNT,
            instance,
        )?;

        key_aggregation_raw_chip
            .bigint_chip()
            .range_chip()
            .load_table(&mut layouter)?;

        key_aggregation_raw_chip
            .bigint_square_chip()
            .range_chip()
            .load_table(&mut layouter)?;

        Ok(())
    }
}

// TODO
#[cfg(test)]
mod tests {
    use crate::key_aggregation::*;
    use crate::MAX_SEQUENCER_NUMBER;

    use halo2wrong::curves::bn256::Fr;
    use maingate::mock_prover_verify;
    use num_bigint::BigUint;
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};
    use std::marker::PhantomData;

    #[test]
    fn test_aggregate_circuit() {
        let mut rng = thread_rng();

        let bit_len = AggregateRawCircuit::<Fr>::BIT_LEN as u64;
        let limb_width = AggregateRawCircuit::<Fr>::LIMB_WIDTH;
        let limb_count = AggregateRawCircuit::<Fr>::LIMB_COUNT;
        let max_sequencer_number = MAX_SEQUENCER_NUMBER;

        let mut n = BigUint::default();
        while n.bits() != bit_len {
            n = rng.sample(RandomBits::new(bit_len));
        }
        let n_square = &n * &n;

        let mut partial_key_list = vec![];

        let mut aggregated_key = AggregatedKey {
            u: BigUint::one(),
            v: BigUint::one(),
            y: BigUint::one(),
            w: BigUint::one(),
        };

        for _ in 0..MAX_SEQUENCER_NUMBER {
            let u = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
            let v = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) % &n_square;
            let y = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
            let w = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) % &n_square;

            partial_key_list.push(PartialKey {
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

        let combined_partial_limbs: Vec<Fr> = PartialKey::decompose_and_combine_all_partial_keys(
            partial_key_list.clone(),
            limb_width,
            limb_count,
        );

        let decomposed_aggregated_key: DecomposedAggregatedKey<Fr> =
            AggregatedKey::decompose_partial_key(&aggregated_key, limb_width, limb_count);
        let mut combined_limbs = decomposed_aggregated_key.combine_limbs();

        let circuit = AggregateRawCircuit::<Fr> {
            n,
            n_square,
            partial_key_list,
            aggregated_key,
            max_sequencer_count: max_sequencer_number,
            _f: PhantomData,
        };

        combined_limbs.extend(combined_partial_limbs);

        let public_inputs = vec![combined_limbs];
        mock_prover_verify(&circuit, public_inputs);
    }
}
