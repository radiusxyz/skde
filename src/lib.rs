pub mod aggregate;
pub mod aggregate_with_hash;
pub mod delay_encryption;

use crate::aggregate::*;
use crate::aggregate_with_hash::*;
use big_integer::*;
use delay_encryption::*;
use poseidon::*;

pub const MAX_SEQUENCER_NUMBER: usize = 2;
pub const BITS_LEN: usize = 2048; // n's bit length
pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BITS_LEN / LIMB_WIDTH;

pub const PRIME_P: &str = "8155133734070055735139271277173718200941522166153710213522626777763679009805792017274916613411023848268056376687809186180768200590914945958831360737612803";
pub const PRIME_Q: &str = "13379153270147861840625872456862185586039997603014979833900847304743997773803109864546170215161716700184487787472783869920830925415022501258643369350348243";
pub const GENERATOR: &str = "4";
pub const TIME_PARAM_T: u32 = 2; // delay time depends on: 2^TIME_PARMA_T

#[cfg(test)]
mod tests {
    use crate::aggregate_with_hash::*;
    use crate::AggregateCircuit;
    use crate::AggregateWithHashCircuit;
    use crate::DecomposedExtractionKey;
    use crate::ExtractionKey;
    use crate::BITS_LEN;
    use crate::MAX_SEQUENCER_NUMBER;
    use poseidon::*;

    use maingate::big_to_fe;
    use maingate::mock_prover_verify;

    use maingate::decompose_big;
    use num_bigint::BigUint;
    use std::marker::PhantomData;

    #[test]
    fn test_aggregate_circuit() {
        use halo2wrong::curves::bn256::Fr;
        use num_bigint::RandomBits;
        use rand::{thread_rng, Rng};
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

        let combined_partial_limbs: Vec<Fr> =
            crate::ExtractionKey::decompose_and_combine_all_partial_keys(partial_keys.clone());

        let decomposed_extraction_key: DecomposedExtractionKey<Fr> =
            crate::ExtractionKey::decompose_extraction_key(&aggregated_key);
        let mut combined_limbs = decomposed_extraction_key.combine_limbs();

        let circuit = AggregateCircuit::<Fr> {
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

    #[test]
    fn test_aggregate_with_hash_circuit() {
        use halo2wrong::curves::bn256::Fr;
        use maingate::mock_prover_verify;
        use num_bigint::RandomBits;
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        let bits_len = AggregateWithHashCircuit::<Fr, 5, 4>::BITS_LEN as u64;
        let mut n = BigUint::default();
        while n.bits() != bits_len {
            n = rng.sample(RandomBits::new(bits_len));
        }
        let n_square = &n * &n;

        let spec = Spec::<Fr, 5, 4>::new(8, 57);

        let mut partial_keys = vec![];

        let mut aggregated_key = ExtractionKey2 {
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

            partial_keys.push(ExtractionKey2 {
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

        let mut ref_hasher = Poseidon::<Fr, 5, 4>::new_hash(8, 57);
        let base1: Fr = big_to_fe(BigUint::from(
            2_u128.pow(
                (AggregateWithHashCircuit::<Fr, 5, 4>::LIMB_WIDTH as u128)
                    .try_into()
                    .unwrap(),
            ),
        ));
        let base2: Fr = base1 * &base1;

        let mut hashes = vec![];

        let limb_width = AggregateWithHashCircuit::<Fr, 5, 4>::LIMB_WIDTH;
        let num_limbs = AggregateWithHashCircuit::<Fr, 5, 4>::BITS_LEN
            / AggregateWithHashCircuit::<Fr, 5, 4>::LIMB_WIDTH;

        for i in 0..MAX_SEQUENCER_NUMBER {
            let u = partial_keys[i].u.clone();
            let u_limbs = decompose_big::<Fr>(u.clone(), num_limbs, limb_width);
            for i in 0..(num_limbs / 3) {
                let mut u_compose = u_limbs[3 * i];
                u_compose += base1 * &u_limbs[3 * i + 1];
                u_compose += base2 * &u_limbs[3 * i + 2];
                ref_hasher.update(&[u_compose]);
            }
            let mut u_compose = u_limbs[30];
            u_compose += base1 * &u_limbs[31];

            let e = u_compose;
            ref_hasher.update(&[e.clone()]);

            let v = partial_keys[i].v.clone();
            let v_limbs = decompose_big::<Fr>(v.clone(), num_limbs * 2, limb_width);
            for i in 0..(num_limbs * 2 / 3) {
                let mut v_compose = v_limbs[3 * i];
                v_compose += base1 * &v_limbs[3 * i + 1];
                v_compose += base2 * &v_limbs[3 * i + 2];
                ref_hasher.update(&[v_compose]);
            }
            let mut v_compose = v_limbs[30];
            v_compose += base1 * &v_limbs[31];
            let e = v_compose;
            ref_hasher.update(&[e.clone()]);

            let y = partial_keys[i].y.clone();
            let y_limbs = decompose_big::<Fr>(y.clone(), num_limbs, limb_width);
            for i in 0..(num_limbs / 3) {
                let mut y_compose = y_limbs[3 * i];
                y_compose += base1 * &y_limbs[3 * i + 1];
                y_compose += base2 * &y_limbs[3 * i + 2];
                ref_hasher.update(&[y_compose]);
            }
            let mut y_compose = y_limbs[30];
            y_compose += base1 * &y_limbs[31];
            let e = y_compose;
            ref_hasher.update(&[e.clone()]);

            let w = partial_keys[i].w.clone();
            let w_limbs = decompose_big::<Fr>(w.clone(), num_limbs * 2, limb_width);
            for i in 0..(num_limbs * 2 / 3) {
                let mut w_compose = w_limbs[3 * i];
                w_compose += base1 * &w_limbs[3 * i + 1];
                w_compose += base2 * &w_limbs[3 * i + 2];
                ref_hasher.update(&[w_compose]);
            }
            let mut w_compose = w_limbs[30];
            w_compose += base1 * &w_limbs[31];
            let e = w_compose;
            ref_hasher.update(&[e.clone()]);
            let hash = ref_hasher.squeeze(1);
            hashes.push(hash[1]);
            hashes.push(hash[2]);
        }

        let circuit = AggregateWithHashCircuit::<Fr, 5, 4> {
            partial_keys,
            n,
            spec,
            n_square,
            _f: PhantomData,
        };

        let mut public_inputs = vec![hashes];
        public_inputs[0].extend(decompose_big::<Fr>(
            aggregated_key.u.clone(),
            num_limbs,
            limb_width,
        ));
        public_inputs[0].extend(decompose_big::<Fr>(
            aggregated_key.v.clone(),
            num_limbs * 2,
            limb_width,
        ));
        public_inputs[0].extend(decompose_big::<Fr>(
            aggregated_key.y.clone(),
            num_limbs,
            limb_width,
        ));
        public_inputs[0].extend(decompose_big::<Fr>(
            aggregated_key.w.clone(),
            num_limbs * 2,
            limb_width,
        ));
        mock_prover_verify(&circuit, public_inputs);
    }
}
