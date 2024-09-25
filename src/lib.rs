pub use big_integer::generate_random_biguint;
use big_integer::mod_exp_by_pow_of_two;
pub use num_bigint::BigUint;

pub mod delay_encryption;
pub mod key_aggregation;
pub mod key_generation;

pub const MAX_SEQUENCER_NUMBER: usize = 2;
pub const BIT_LEN: usize = 2048; // n's bit length
pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BIT_LEN / LIMB_WIDTH;

pub const PRIME_P: &str = "8155133734070055735139271277173718200941522166153710213522626777763679009805792017274916613411023848268056376687809186180768200590914945958831360737612803";
pub const PRIME_Q: &str = "13379153270147861840625872456862185586039997603014979833900847304743997773803109864546170215161716700184487787472783869920830925415022501258643369350348243";
pub const GENERATOR: &str = "4";
pub const TIME_PARAM_T: u32 = 2; // delay time depends on: 2^TIME_PARMA_T

#[derive(Debug, Clone)]
pub struct SkdeParams {
    pub n: BigUint, // RSA modulus n = p * q
    pub g: BigUint, // group generator
    pub t: u32,     // delay parameter
    pub h: BigUint, // g^{2^t} mod n

    pub max_sequencer_number: BigUint,
}

pub fn setup(
    t: u32,
    p: BigUint,
    q: BigUint,
    g: BigUint,
    max_sequencer_number: BigUint,
) -> SkdeParams {
    let n = p * q;
    let h = mod_exp_by_pow_of_two(&g, t, &n);

    SkdeParams {
        n,
        g,
        t,
        h,
        max_sequencer_number,
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Instant};

    use crate::{
        delay_encryption::{decrypt, encrypt, solve_time_lock_puzzle, PublicKey},
        key_aggregation::aggregate_key,
        key_generation::{
            generate_partial_key, prove_partial_key_validity, verify_partial_key_validity,
        },
        setup,
    };

    use num_bigint::BigUint;

    use crate::{GENERATOR, MAX_SEQUENCER_NUMBER, PRIME_P, PRIME_Q, TIME_PARAM_T};

    #[test]
    fn test_single_key_delay_encryption() {
        let time = 2_u32.pow(TIME_PARAM_T);
        let p = BigUint::from_str(PRIME_P).expect("Invalid PRIME_P");
        let q = BigUint::from_str(PRIME_Q).expect("Invalid PRIME_Q");
        let g = BigUint::from_str(GENERATOR).expect("Invalid GENERATOR");
        let max_sequencer_number = BigUint::from(MAX_SEQUENCER_NUMBER);

        let skde_params = setup(time, p, q, g, max_sequencer_number);
        // TODO: DH
        let message: &str = "0xf869018203e882520894f17f52151ebef6c7334fad080c5704d77216b732881bc16d674ec80000801ba02da1c48b670996dcb1f447ef9ef00b33033c48a4fe";

        // 1. Generate partial keys and proofs
        let generated_keys_and_proofs: Vec<_> = (0..MAX_SEQUENCER_NUMBER)
            .enumerate()
            .map(|(index, _)| {
                let start = Instant::now();
                let (secret_value, partial_key) = generate_partial_key(&skde_params);
                let key_proof = prove_partial_key_validity(&skde_params, &secret_value);
                let generation_duration = start.elapsed();
                println!(
                    "Sequencer{}'s key and proof generation time: {:?}",
                    index + 1,
                    generation_duration
                );
                (partial_key, key_proof)
            })
            .collect();

        // 2. Verify all generated keys
        let verification_start = Instant::now();
        generated_keys_and_proofs
            .iter()
            .for_each(|(partial_key, key_proof)| {
                assert!(
                    verify_partial_key_validity(
                        &skde_params,
                        partial_key.clone(),
                        key_proof.clone()
                    ),
                    "Key verification failed"
                );
            });
        let verification_duration = verification_start.elapsed();

        println!(
            "Total key verification time for {} keys: {:?}",
            MAX_SEQUENCER_NUMBER, verification_duration
        );

        let partial_key_list = generated_keys_and_proofs
            .into_iter()
            .map(|(partial_key, _)| partial_key)
            .collect();

        // 3. Aggregate all partial keys
        let aggregation_start = Instant::now();
        let aggregated_key = aggregate_key(&skde_params, &partial_key_list);
        let aggregation_duration = aggregation_start.elapsed();
        println!("Aggregation time: {:?}", aggregation_duration);

        let encryption_key = PublicKey {
            pk: aggregated_key.u.clone(),
        };

        // 4. Encrypt the message
        let encryption_start = Instant::now();
        let cipher_text = encrypt(&skde_params, message, &encryption_key).unwrap();
        let encryption_duration = encryption_start.elapsed();
        println!("Encryption time: {:?}", encryption_duration);

        // 5. Solve the time-lock puzzle
        let puzzle_start = Instant::now();
        let secret_key = solve_time_lock_puzzle(&skde_params, &aggregated_key).unwrap();
        let puzzle_duration = puzzle_start.elapsed();
        println!("Puzzle solved time: {:?}", puzzle_duration);

        // 6. Decrypt the cipher text
        let decryption_start = Instant::now();
        let decrypted_message = decrypt(&skde_params, &cipher_text, &secret_key).unwrap();
        let decryption_duration = decryption_start.elapsed();
        println!("Decryption time: {:?}", decryption_duration);

        assert_eq!(
            message, decrypted_message,
            "Decrypted message does not same with the original message"
        );
    }
}
