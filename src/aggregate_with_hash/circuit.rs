use crate::aggregate_with_hash::*;
use big_integer::*;
use ff::FromUniformBytes;
use ff::PrimeField;
use halo2wrong::{
    halo2::{
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem, Error},
    },
    RegionCtx,
};
use maingate::big_to_fe;
use maingate::MainGateInstructions;
use maingate::{decompose_big, MainGate, RangeChip, RangeInstructions};
use num_bigint::BigUint;
use poseidon::*;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct AggregateWithHashCircuit<F: PrimeField, const T: usize, const RATE: usize> {
    pub partial_keys: Vec<ExtractionKey2>,
    pub n: BigUint,
    pub spec: Spec<F, T, RATE>,
    pub n_square: BigUint,
    pub _f: PhantomData<F>,
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize>
    AggregateWithHashCircuit<F, T, RATE>
{
    pub const BITS_LEN: usize = 2048; // n's bit length
    pub const LIMB_WIDTH: usize = AggregateWithHashChip::<F, T, RATE>::LIMB_WIDTH;
    fn aggregate_with_hash_chip(
        &self,
        config: AggregateWithHashConfig,
    ) -> AggregateWithHashChip<F, T, RATE> {
        AggregateWithHashChip::new(config, Self::BITS_LEN)
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for AggregateWithHashCircuit<F, T, RATE>
{
    type Config = AggregateWithHashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        let (composition_bit_lens, overflow_bit_lens) =
            AggregateWithHashChip::<F, T, RATE>::compute_range_lens(
                Self::BITS_LEN / Self::LIMB_WIDTH,
            );
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );
        let (square_composition_bit_lens, square_overflow_bit_lens) =
            AggregateWithHashChip::<F, T, RATE>::compute_range_lens(
                Self::BITS_LEN * 2 / Self::LIMB_WIDTH,
            );
        let square_range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            square_composition_bit_lens,
            square_overflow_bit_lens,
        );
        let bigint_config = BigIntConfig::new(range_config.clone(), main_gate_config.clone());
        let bigint_square_config =
            BigIntConfig::new(square_range_config.clone(), main_gate_config.clone());

        let hash_config = main_gate_config.clone();

        Self::Config {
            bigint_config,
            bigint_square_config,
            hash_config,
            instance: meta.instance_column(),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        let limb_width = Self::LIMB_WIDTH;
        let num_limbs = Self::BITS_LEN / Self::LIMB_WIDTH;
        let aggregate_with_hash_chip = self.aggregate_with_hash_chip(config.clone());
        let bigint_chip = aggregate_with_hash_chip.bigint_chip();
        let main_gate_chip = bigint_chip.main_gate();
        let bigint_square_chip = aggregate_with_hash_chip.bigint_square_chip();

        let instances = config.instance;

        // let instances = bigint_chip.get_instance();

        let (u_out, v_out, y_out, w_out) = layouter.assign_region(
            || "Pick 2048bit u for partial keys",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut u_out = vec![];
                let mut v_out = vec![];
                let mut y_out = vec![];
                let mut w_out = vec![];
                for i in 0..MAX_SEQUENCER_NUMBER {
                    let u_limbs =
                        decompose_big::<F>(self.partial_keys[i].u.clone(), num_limbs, limb_width);
                    let u_unassigned = UnassignedInteger::from(u_limbs);
                    let u_assigned = bigint_chip.assign_integer(ctx, u_unassigned)?;
                    u_out.push(u_assigned);

                    let v_limbs = decompose_big::<F>(
                        self.partial_keys[i].v.clone(),
                        num_limbs * 2,
                        limb_width,
                    );
                    let v_unassigned = UnassignedInteger::from(v_limbs);
                    let v_assigned = bigint_square_chip.assign_integer(ctx, v_unassigned)?;
                    v_out.push(v_assigned);

                    let y_limbs =
                        decompose_big::<F>(self.partial_keys[i].y.clone(), num_limbs, limb_width);
                    let y_unassigned = UnassignedInteger::from(y_limbs);
                    let y_assigned = bigint_chip.assign_integer(ctx, y_unassigned)?;
                    y_out.push(y_assigned);

                    let w_limbs = decompose_big::<F>(
                        self.partial_keys[i].w.clone(),
                        num_limbs * 2,
                        limb_width,
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
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut hasher = AggregateWithHashChip::<F, T, RATE>::new_hash(
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
                // println!("base1 = {:?}", base1);

                let mut hash_out = vec![];
                for i in 0..MAX_SEQUENCER_NUMBER {
                    let u = u_out[i].clone();
                    for j in 0..u.num_limbs() / 3 {
                        // println!("limb({:?}) = {:?}", 3 * i, rsa_input.limb(3 * i));
                        // println!("limb({:?}) = {:?}", 3 * i + 1, rsa_input.limb(3 * i + 1));
                        // println!("limb({:?}) = {:?}", 3 * i + 2, rsa_input.limb(3 * i + 2));
                        let mut a_poly = u.limb(3 * j);
                        a_poly =
                            main_gate_chip.mul_add(ctx, &u.limb(3 * j + 1), &base1, &a_poly)?;
                        a_poly =
                            main_gate_chip.mul_add(ctx, &u.limb(3 * j + 2), &base2, &a_poly)?;
                        // println!("a_ploy value:{:?}", a_poly);
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
            layouter.constrain_instance(hash.cell(), instances, index)?;
            index += 1;
        }

        let valid_aggregated_key = layouter.assign_region(
            || "aggregate test with 2048 bits RSA parameter",
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
                    let assigned_extraction_key = AssignedAggregateWithHashExtractionKey::new(
                        u_out[i].clone(),
                        v_out[i].clone(),
                        y_out[i].clone(),
                        w_out[i].clone(),
                    );
                    partial_keys_assigned.push(assigned_extraction_key);
                }
                let partial_keys = AssignedAggregateWithHashPartialKeys::new(partial_keys_assigned);

                let public_params_unassigned = AggregateWithHashPublicParams::new(
                    n_unassigned.clone(),
                    n_square_unassigned.clone(),
                );
                let public_params =
                    aggregate_with_hash_chip.assign_public_params(ctx, public_params_unassigned)?;
                let valid_aggregated_key = aggregate_with_hash_chip.aggregate_with_hash(
                    ctx,
                    &partial_keys.clone(),
                    &public_params.clone(),
                )?;

                Ok(valid_aggregated_key)
            },
        )?;

        (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.u.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;
        (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.v.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;
        (0..num_limbs).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.y.limb(i).cell(), instances, index)?;
            index += 1;
            Ok(())
        })?;
        (0..num_limbs * 2).try_for_each(|i| -> Result<(), Error> {
            layouter.constrain_instance(valid_aggregated_key.w.limb(i).cell(), instances, index)?;
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
