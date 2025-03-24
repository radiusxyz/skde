pub use big_integer::generate_random_biguint;
use delay_encryption::SkdeParams;
pub use num_bigint::BigUint;
pub use num_prime::RandPrime;

pub mod delay_encryption;
pub mod key_aggregation;
pub mod key_generation;

pub const MAX_SEQUENCER_NUMBER: usize = 2;
pub const BIT_LEN: usize = 2048; // n's bit length

pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BIT_LEN / LIMB_WIDTH;

pub const GENERATOR: &str = "4"; // g = 4 is safe as long as gcd(g, n) = 1 (i.e., g is invertible mod n)
pub const TIME_PARAM_T: u32 = 2;

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Instant};

    use big_integer::mod_exp_by_pow_of_two;
    use num_bigint::BigUint;
    use rand::{distributions::Alphanumeric, Rng};

    use crate::{
        delay_encryption::{decrypt, encrypt, setup, solve_time_lock_puzzle, SkdeParams},
        key_aggregation::aggregate_key,
        key_generation::{
            generate_partial_key, prove_partial_key_validity, verify_partial_key_validity,
        },
        BIT_LEN, GENERATOR, MAX_SEQUENCER_NUMBER, TIME_PARAM_T,
    };

    // Predefined RSA modulus for deterministic encryption test
    pub const MOD_N: &str = "109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129";

    /// For testing: returns SKDE parameters using predefined constant modulus
    /// `MOD_N` This avoids generating expensive safe primes every time
    fn default_skde_params() -> SkdeParams {
        let n = BigUint::from_str(MOD_N).unwrap();
        let g = BigUint::from_str(GENERATOR).unwrap();
        let t = 2_u32.pow(TIME_PARAM_T);
        let h = mod_exp_by_pow_of_two(&g, t, &n);
        let max_seq = BigUint::from(MAX_SEQUENCER_NUMBER as u32);

        SkdeParams {
            t,
            n: n.to_str_radix(10),
            g: g.to_str_radix(10),
            h: h.to_str_radix(10),
            max_sequencer_number: max_seq.to_str_radix(10),
        }
    }

    /// Tests the correctness of the `setup` function and generated parameters.
    /// Ensures all fields are consistent and `n` is sufficiently large.
    #[test]
    fn test_secure_setup() {
        let g = BigUint::from_str(GENERATOR).unwrap();
        let max_seq = BigUint::from(MAX_SEQUENCER_NUMBER as u32);

        // Warning: this may not be efficient for runtime tests
        let skde_params = setup(TIME_PARAM_T, g.clone(), max_seq.clone());

        let n = BigUint::from_str(&skde_params.n).unwrap();
        let h = BigUint::from_str(&skde_params.h).unwrap();
        let computed_h = mod_exp_by_pow_of_two(&g, TIME_PARAM_T, &n);

        assert_eq!(skde_params.g, g.to_str_radix(10), "Generator mismatch");
        assert_eq!(
            skde_params.max_sequencer_number,
            max_seq.to_str_radix(10),
            "Max sequencer mismatch"
        );
        assert_eq!(h, computed_h, "h is not computed correctly");
        assert_eq!(skde_params.t, TIME_PARAM_T, "Time parameter mismatch");
        assert!(n.bits() >= BIT_LEN as u64, "Modulus too small");
        // assert!(n.is_odd(), "Modulus n should be odd");
    }

    #[test]
    fn test_single_key_delay_encryption() {
        // 1. Set skde parameters
        let skde_params = default_skde_params();
        let message: &str = "12345";

        // 2. Generate partial keys and proofs
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

        // 3. Verify all generated keys
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

        let partial_keys = generated_keys_and_proofs
            .into_iter()
            .map(|(partial_key, _)| partial_key)
            .collect();

        // 4. Aggregate all partial keys
        let aggregation_start = Instant::now();
        let aggregated_key = aggregate_key(&skde_params, &partial_keys);
        let aggregation_duration = aggregation_start.elapsed();
        println!("Aggregation time: {:?}", aggregation_duration);

        let encryption_key = aggregated_key.u.clone();

        println!("Encryption key: {:?}", encryption_key);

        // 5. Encrypt the message
        let encryption_start = Instant::now();
        let cipher_text = encrypt(&skde_params, message, &encryption_key, false).unwrap();
        let encryption_duration = encryption_start.elapsed();
        println!("Encryption time: {:?}", encryption_duration);

        // 6. Solve the time-lock puzzle
        let puzzle_start = Instant::now();
        let secret_key = solve_time_lock_puzzle(&skde_params, &aggregated_key).unwrap();
        let puzzle_duration = puzzle_start.elapsed();
        println!("Puzzle solved time: {:?}", puzzle_duration);

        // 7. Decrypt the cipher text
        let decryption_start = Instant::now();
        let decrypted_message = decrypt(&skde_params, &cipher_text, &secret_key.sk).unwrap();
        let decryption_duration = decryption_start.elapsed();
        println!("Decryption time: {:?}", decryption_duration);

        assert_eq!(
            message, decrypted_message,
            "Decrypted message is not the same with the original message"
        );
    }

    #[test]
    fn reps() {
        // Repeats the full encryption-decryption test multiple times for robustness
        for _ in 0..10 {
            test_single_key_delay_encryption();
        }
    }

    /// Generates a random ASCII string of the specified byte length.
    /// Only alphanumeric ASCII characters (A-Z, a-z, 0-9) are used.
    ///
    /// # Arguments
    /// * `len` - The desired length of the message in bytes
    ///
    /// # Returns
    /// * A `String` of exactly `len` bytes
    fn generate_random_message(len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    /// Tests encryption with a longer message (edge case)
    #[test]
    fn test_long_message_encryption() {
        let skde_params = default_skde_params();
        let message = generate_random_message(350);

        let (secret_value, partial_key) = generate_partial_key(&skde_params);
        let key_proof = prove_partial_key_validity(&skde_params, &secret_value);
        assert!(verify_partial_key_validity(
            &skde_params,
            partial_key.clone(),
            key_proof
        ));

        let aggregated_key = aggregate_key(&skde_params, &vec![partial_key]);
        let cipher_text = encrypt(&skde_params, &message, &aggregated_key.u, false).unwrap();
        let secret_key = solve_time_lock_puzzle(&skde_params, &aggregated_key).unwrap();
        let decrypted_message = decrypt(&skde_params, &cipher_text, &secret_key.sk).unwrap();

        assert_eq!(
            message, decrypted_message,
            "Decryption failed for long message"
        );
    }
}
