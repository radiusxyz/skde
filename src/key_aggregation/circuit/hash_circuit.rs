use std::marker::PhantomData;

use big_integer::*;
use ff::{FromUniformBytes, PrimeField};
use halo2wrong::{
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem, Error},
    },
    RegionCtx,
};
use maingate::{
    big_to_fe, decompose_big, MainGate, MainGateInstructions, RangeChip, RangeInstructions,
};
use num_bigint::BigUint;
use poseidon::*;

use crate::{key_aggregation::*, key_generation::AssignedPartialKey, BIT_LEN, LIMB_WIDTH};

#[derive(Clone, Debug)]
pub struct AggregateHashCircuit<F: PrimeField, const T: usize, const RATE: usize> {
    pub spec: Spec<F, T, RATE>,

    pub n: BigUint,
    pub n_square: BigUint,

    pub partial_key_list: Vec<PartialKey>,

    pub max_sequencer_number: usize,

    pub _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateHashCircuit<F, T, RATE>
{
    pub const BIT_LEN: usize = BIT_LEN;
    pub const LIMB_WIDTH: usize = LIMB_WIDTH;
    pub const LIMB_COUNT: usize = BIT_LEN / LIMB_WIDTH;

    fn key_aggregation_chip(
        &self,
        config: AggregateHashConfig,
    ) -> KeyAggregationHashChip<F, T, RATE> {
        KeyAggregationHashChip::new(
            config,
            Self::BIT_LEN,
            Self::LIMB_WIDTH,
            self.max_sequencer_number,
        )
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for AggregateHashCircuit<F, T, RATE>
{
    type Config = AggregateHashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);

        let (composition_bit_lens, overflow_bit_lens) =
            KeyAggregationHashChip::<F, T, RATE>::compute_range_lens(
                Self::LIMB_WIDTH,
                Self::LIMB_COUNT,
            );
        let (square_composition_bit_lens, square_overflow_bit_lens) =
            KeyAggregationHashChip::<F, T, RATE>::compute_range_lens(
                Self::LIMB_WIDTH,
                Self::LIMB_COUNT * 2,
            );

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
            bigint_square_config: BigIntConfig::new(square_range_config, main_gate_config.clone()),
            hash_config: main_gate_config,
            instance: meta.instance_column(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        let instance = config.instance;
        let key_aggregation_chip = self.key_aggregation_chip(config.clone());

        let bigint_chip = key_aggregation_chip.bigint_chip();
        let bigint_square_chip = key_aggregation_chip.bigint_square_chip();
        let main_gate_chip = bigint_chip.main_gate();

        let (u_out, v_out, y_out, w_out) = layouter.assign_region(
            || "Pick 2048bit u for partial keys",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let mut u_out = vec![];
                let mut v_out = vec![];
                let mut y_out = vec![];
                let mut w_out = vec![];

                for i in 0..self.max_sequencer_number {
                    let u_limbs = decompose_big::<F>(
                        self.partial_key_list[i].u.clone(),
                        Self::LIMB_COUNT,
                        Self::LIMB_WIDTH,
                    );

                    let u_unassigned = UnassignedInteger::from(u_limbs);
                    let u_assigned = bigint_chip.assign_integer(ctx, u_unassigned)?;
                    u_out.push(u_assigned);

                    let v_limbs = decompose_big::<F>(
                        self.partial_key_list[i].v.clone(),
                        Self::LIMB_COUNT * 2,
                        Self::LIMB_WIDTH,
                    );
                    let v_unassigned = UnassignedInteger::from(v_limbs);
                    let v_assigned = bigint_square_chip.assign_integer(ctx, v_unassigned)?;
                    v_out.push(v_assigned);

                    let y_limbs = decompose_big::<F>(
                        self.partial_key_list[i].y.clone(),
                        Self::LIMB_COUNT,
                        Self::LIMB_WIDTH,
                    );
                    let y_unassigned = UnassignedInteger::from(y_limbs);
                    let y_assigned = bigint_chip.assign_integer(ctx, y_unassigned)?;
                    y_out.push(y_assigned);

                    let w_limbs = decompose_big::<F>(
                        self.partial_key_list[i].w.clone(),
                        Self::LIMB_COUNT * 2,
                        Self::LIMB_WIDTH,
                    );
                    let w_unassigned = UnassignedInteger::from(w_limbs);
                    let w_assigned = bigint_square_chip.assign_integer(ctx, w_unassigned)?;
                    w_out.push(w_assigned);
                }
                Ok((u_out, v_out, y_out, w_out))
            },
        )?;

        let hash_out = layouter.assign_region(
            || "hash mapping from 2048bit",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let mut hasher = KeyAggregationHashChip::<F, T, RATE>::new_hash(
                    ctx,
                    &self.spec,
                    &config.hash_config.clone(),
                )?;

                let base1 = main_gate_chip.assign_constant(
                    ctx,
                    big_to_fe(BigUint::from(
                        2_u128.pow((Self::LIMB_WIDTH as u128).try_into().unwrap()),
                    )),
                )?;
                let base2 = main_gate_chip.mul(ctx, &base1, &base1)?;

                let mut hash_out = vec![];

                for i in 0..self.max_sequencer_number {
                    let u = u_out[i].clone();

                    for j in 0..u.num_limbs() / 3 {
                        let mut a_poly = u.limb(3 * j);
                        a_poly =
                            main_gate_chip.mul_add(ctx, &u.limb(3 * j + 1), &base1, &a_poly)?;
                        a_poly =
                            main_gate_chip.mul_add(ctx, &u.limb(3 * j + 2), &base2, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);
                    }

                    let mut a_poly = u.limb(30);

                    a_poly = main_gate_chip.mul_add(ctx, &u.limb(31), &base1, &a_poly)?;
                    let e = a_poly;
                    hasher.update(&[e.clone()]);

                    let v = v_out[i].clone();
                    for j in 0..v.num_limbs() / 3 {
                        let mut a_poly = v.limb(3 * j);
                        a_poly =
                            main_gate_chip.mul_add(ctx, &v.limb(3 * j + 1), &base1, &a_poly)?;
                        a_poly =
                            main_gate_chip.mul_add(ctx, &v.limb(3 * j + 2), &base2, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);
                    }

                    let mut a_poly = v.limb(30);

                    a_poly = main_gate_chip.mul_add(ctx, &v.limb(31), &base1, &a_poly)?;
                    let e = a_poly;
                    hasher.update(&[e.clone()]);

                    let y = y_out[i].clone();
                    for j in 0..y.num_limbs() / 3 {
                        let mut a_poly = y.limb(3 * j);
                        a_poly =
                            main_gate_chip.mul_add(ctx, &y.limb(3 * j + 1), &base1, &a_poly)?;
                        a_poly =
                            main_gate_chip.mul_add(ctx, &y.limb(3 * j + 2), &base2, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);
                    }

                    let mut a_poly = y.limb(30);

                    a_poly = main_gate_chip.mul_add(ctx, &y.limb(31), &base1, &a_poly)?;
                    let e = a_poly;
                    hasher.update(&[e.clone()]);

                    let w = w_out[i].clone();
                    for j in 0..w.num_limbs() / 3 {
                        let mut a_poly = w.limb(3 * j);
                        a_poly =
                            main_gate_chip.mul_add(ctx, &w.limb(3 * j + 1), &base1, &a_poly)?;
                        a_poly =
                            main_gate_chip.mul_add(ctx, &w.limb(3 * j + 2), &base2, &a_poly)?;
                        let e = a_poly;
                        hasher.update(&[e.clone()]);
                    }

                    let mut a_poly = w.limb(30);

                    a_poly = main_gate_chip.mul_add(ctx, &w.limb(31), &base1, &a_poly)?;
                    let e = a_poly;
                    hasher.update(&[e.clone()]);

                    let h_assiged = hasher.hash(ctx)?;
                    hash_out.push(h_assiged[1].clone());
                    hash_out.push(h_assiged[2].clone());
                }
                Ok(hash_out)
            },
        )?;

        let mut index = 0;
        for hash in hash_out.iter() {
            layouter.constrain_instance(hash.cell(), instance, index)?;
            index += 1;
        }

        let n_limbs = decompose_big::<F>(self.n.clone(), Self::LIMB_COUNT, Self::LIMB_WIDTH);
        let n_unassigned = UnassignedInteger::from(n_limbs);

        let n_square_limbs = decompose_big::<F>(
            self.n_square.clone(),
            Self::LIMB_COUNT * 2,
            Self::LIMB_WIDTH,
        );
        let n_square_unassigned = UnassignedInteger::from(n_square_limbs);

        let aggregated_key = layouter.assign_region(
            || "aggregate test with 2048 bits RSA parameter",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let mut assigned_partial_key_list = vec![];

                for i in 0..self.max_sequencer_number {
                    let assigned_extraction_key = AssignedPartialKey::new(
                        u_out[i].clone(),
                        v_out[i].clone(),
                        y_out[i].clone(),
                        w_out[i].clone(),
                    );
                    assigned_partial_key_list.push(assigned_extraction_key);
                }
                let assigned_extraction_key = AssignedExtractionKey {
                    partial_key_list: assigned_partial_key_list,
                };

                let public_params_unassigned = UnassignedKeyAggregationPublicParams {
                    n: n_unassigned.clone(),
                    n_square: n_square_unassigned.clone(),
                };

                let public_params = assign_public_params(
                    ctx,
                    key_aggregation_chip.bigint_chip(),
                    key_aggregation_chip.bigint_square_chip(),
                    public_params_unassigned,
                )?;

                let valid_aggregated_key = aggregate_assigned_key(
                    ctx,
                    key_aggregation_chip.bigint_chip(),
                    key_aggregation_chip.bigint_square_chip(),
                    key_aggregation_chip.max_sequencer_number(),
                    &assigned_extraction_key.clone(),
                    &public_params.clone(),
                )?;

                Ok(valid_aggregated_key)
            },
        )?;

        let instance = config.instance;

        (0..Self::LIMB_COUNT).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(aggregated_key.u.limb(i).cell(), instance, index)?;
            index += 1;
            Ok(())
        })?;

        (0..Self::LIMB_COUNT * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(aggregated_key.v.limb(i).cell(), instance, index)?;
            index += 1;
            Ok(())
        })?;

        (0..Self::LIMB_COUNT).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(aggregated_key.y.limb(i).cell(), instance, index)?;
            index += 1;
            Ok(())
        })?;

        (0..Self::LIMB_COUNT * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(aggregated_key.w.limb(i).cell(), instance, index)?;
            index += 1;
            Ok(())
        })?;

        let range_chip = bigint_chip.range_chip();
        let range_square_chip = bigint_square_chip.range_chip();
        range_chip.load_table(&mut layouter)?;
        range_square_chip.load_table(&mut layouter)?;

        Ok(())
    }
}

// TODO: Refactoring
// #[cfg(test)]
// mod tests {
//     use std::marker::PhantomData;

//     use halo2wrong::curves::bn256::Fr;
//     use maingate::{big_to_fe, decompose_big, mock_prover_verify};
//     use num_bigint::{BigUint, RandomBits};
//     use poseidon::{Poseidon, Spec};
//     use rand::{thread_rng, Rng};

//     use crate::{key_aggregation::*, BIT_LEN, MAX_SEQUENCER_NUMBER};

//     #[test]
//     fn test_aggregate_with_hash_circuit() {
//         let bit_len = BIT_LEN as u64;
//         let max_sequencer_number = MAX_SEQUENCER_NUMBER;
//         let limb_width = AggregateHashCircuit::<Fr, 5, 4>::LIMB_WIDTH;
//         let limb_count = AggregateHashCircuit::<Fr, 5, 4>::LIMB_COUNT;

//         let mut rng = thread_rng();

//         let mut n = BigUint::default();
//         while n.bits() != bit_len {
//             n = rng.sample(RandomBits::new(bit_len));
//         }
//         let n_square = &n * &n;

//         let spec = Spec::<Fr, 5, 4>::new(8, 57);

//         let mut partial_key_list = vec![];

//         let mut aggregated_key = AggregatedKey {
//             u: BigUint::one().to_str_radix(10),
//             v: BigUint::one().to_str_radix(10),
//             y: BigUint::one().to_str_radix(10),
//             w: BigUint::one().to_str_radix(10),
//         };

//         for _ in 0..max_sequencer_number {
//             let u = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
//             let v = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) %
// &n_square;             let y = rng.sample::<BigUint,
// _>(RandomBits::new(bit_len)) % &n;             let w = rng.sample::<BigUint,
// _>(RandomBits::new(bit_len * 2)) % &n_square;

//             partial_key_list.push(PartialKey {
//                 u: u.clone(),
//                 v: v.clone(),
//                 y: y.clone(),
//                 w: w.clone(),
//             });

//             aggregated_key.u = (BigUint::from_str_radix(&aggregated_key.u,
// 10).unwrap() * &u % &n)                 .to_str_radix(10);
//             aggregated_key.v = (BigUint::from_str_radix(&aggregated_key.v,
// 10).unwrap() * &v                 % &n_square)
//                 .to_str_radix(10);
//             aggregated_key.y = (BigUint::from_str_radix(&aggregated_key.y,
// 10).unwrap() * &y % &n)                 .to_str_radix(10);
//             aggregated_key.w = (BigUint::from_str_radix(&aggregated_key.w,
// 10).unwrap() * &w                 % &n_square)
//                 .to_str_radix(10);
//         }

//         let mut ref_hasher = Poseidon::<Fr, 5, 4>::new_hash(8, 57);

//         let base1: Fr = big_to_fe(BigUint::from(
//             2_u128.pow((limb_width as u128).try_into().unwrap()),
//         ));
//         let base2: Fr = base1 * &base1;

//         let mut hash_list = vec![];

//         for i in 0..max_sequencer_number {
//             let u = partial_key_list[i].u.clone();
//             let u_limbs = decompose_big::<Fr>(u.clone(), limb_count,
// limb_width);             for i in 0..(limb_count / 3) {
//                 let mut u_compose = u_limbs[3 * i];
//                 u_compose += base1 * &u_limbs[3 * i + 1];
//                 u_compose += base2 * &u_limbs[3 * i + 2];
//                 ref_hasher.update(&[u_compose]);
//             }
//             let mut u_compose = u_limbs[30];
//             u_compose += base1 * &u_limbs[31];

//             let e = u_compose;
//             ref_hasher.update(&[e.clone()]);

//             let v = partial_key_list[i].v.clone();
//             let v_limbs = decompose_big::<Fr>(v.clone(), limb_count * 2,
// limb_width);             for i in 0..(limb_count * 2 / 3) {
//                 let mut v_compose = v_limbs[3 * i];
//                 v_compose += base1 * &v_limbs[3 * i + 1];
//                 v_compose += base2 * &v_limbs[3 * i + 2];
//                 ref_hasher.update(&[v_compose]);
//             }
//             let mut v_compose = v_limbs[30];
//             v_compose += base1 * &v_limbs[31];

//             let e = v_compose;
//             ref_hasher.update(&[e.clone()]);

//             let y = partial_key_list[i].y.clone();
//             let y_limbs = decompose_big::<Fr>(y.clone(), limb_count,
// limb_width);             for i in 0..(limb_count / 3) {
//                 let mut y_compose = y_limbs[3 * i];
//                 y_compose += base1 * &y_limbs[3 * i + 1];
//                 y_compose += base2 * &y_limbs[3 * i + 2];
//                 ref_hasher.update(&[y_compose]);
//             }
//             let mut y_compose = y_limbs[30];
//             y_compose += base1 * &y_limbs[31];

//             let e = y_compose;
//             ref_hasher.update(&[e.clone()]);

//             let w = partial_key_list[i].w.clone();
//             let w_limbs = decompose_big::<Fr>(w.clone(), limb_count * 2,
// limb_width);             for i in 0..(limb_count * 2 / 3) {
//                 let mut w_compose = w_limbs[3 * i];
//                 w_compose += base1 * &w_limbs[3 * i + 1];
//                 w_compose += base2 * &w_limbs[3 * i + 2];
//                 ref_hasher.update(&[w_compose]);
//             }
//             let mut w_compose = w_limbs[30];
//             w_compose += base1 * &w_limbs[31];

//             let e = w_compose;
//             ref_hasher.update(&[e.clone()]);

//             let hash = ref_hasher.squeeze(1);
//             hash_list.push(hash[1]);
//             hash_list.push(hash[2]);
//         }

//         let circuit = AggregateHashCircuit::<Fr, 5, 4> {
//             spec,
//             n,
//             n_square,
//             partial_key_list,
//             max_sequencer_number,
//             _f: PhantomData,
//         };

//         let bit_len = BIT_LEN;

//         let mut public_inputs = vec![hash_list];
//         public_inputs[0].extend(decompose_big::<Fr>(
//             BigUint::from_str_radix(&aggregated_key.u, 10).unwrap(),
//             limb_count,
//             bit_len,
//         ));

//         public_inputs[0].extend(decompose_big::<Fr>(
//             BigUint::from_str_radix(&aggregated_key.v, 10).unwrap(),
//             limb_count * 2,
//             bit_len,
//         ));

//         public_inputs[0].extend(decompose_big::<Fr>(
//             BigUint::from_str_radix(&aggregated_key.y, 10).unwrap(),
//             limb_count,
//             bit_len,
//         ));

//         public_inputs[0].extend(decompose_big::<Fr>(
//             BigUint::from_str_radix(&aggregated_key.w, 10).unwrap(),
//             limb_count * 2,
//             bit_len,
//         ));

//         mock_prover_verify(&circuit, public_inputs);
//     }
// }
