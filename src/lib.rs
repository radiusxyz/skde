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
    use num_integer::Integer;
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

    struct BenchmarkResult {
        message_len: usize,
        // encryption_type: String,
        encryption_time: std::time::Duration,
        puzzle_time: std::time::Duration,
        decryption_time: std::time::Duration,
        ciphertext_size: usize,
    }

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

    /// Generates a random ASCII string of the specified byte length.
    /// Only characters (A-Z, a-z, 0-9) are used.
    /// Therefore, a string of length `len` is exactly `len` bytes in size
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

    fn run_encryption_benchmark(hybrid: bool, message_len: usize) -> BenchmarkResult {
        // Set skde parameters
        let skde_params = default_skde_params();
        let message = generate_random_message(message_len);

        // let encryption_type = if hybrid { "Hybrid" } else { "Standard" };

        // Generate partial keys & Verify all
        let partial_keys: Vec<_> = (0..MAX_SEQUENCER_NUMBER)
            .map(|_| {
                let (secret, partial) = generate_partial_key(&skde_params);
                let proof = prove_partial_key_validity(&skde_params, &secret);
                assert!(verify_partial_key_validity(
                    &skde_params,
                    partial.clone(),
                    proof
                ));
                partial
            })
            .collect();

        // Aggregate key
        let aggregated_key = aggregate_key(&skde_params, &partial_keys);
        let encryption_key = aggregated_key.u.clone();

        // Encryption
        let t1 = Instant::now();
        let ciphertext = encrypt(&skde_params, &message, &encryption_key, hybrid).unwrap();
        let encryption_time = t1.elapsed();
        let ciphertext_size = ciphertext.len();

        // Puzzle solve
        let t2 = Instant::now();
        let secret_key = solve_time_lock_puzzle(&skde_params, &aggregated_key).unwrap();
        let puzzle_time = t2.elapsed();

        // Decryption
        let t3 = Instant::now();
        let decrypted = decrypt(&skde_params, &ciphertext, &secret_key.sk).unwrap();
        let decryption_time = t3.elapsed();

        assert_eq!(message, decrypted);

        BenchmarkResult {
            message_len,
            // encryption_type: encryption_type.to_string(),
            encryption_time,
            puzzle_time,
            decryption_time,
            ciphertext_size,
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
        assert!(n.is_odd(), "Modulus n should be odd");
    }

    #[test]
    fn benchmark_standard_vs_hybrid_various_lengths() {
        let mut results = Vec::new();

        for &len in &[64, 128, 256, 512, 1024, 2048] {
            let standard = run_encryption_benchmark(false, len);
            let hybrid = run_encryption_benchmark(true, len);
            results.push((standard, hybrid));
        }
        // Print performance table with ciphertext sizes
        println!("{:<8} | {:^43} | {:^43}", "Bytes", "Standard", "Hybrid");
        println!("{}", "-".repeat(100));
        println!(
            "{:<8} | {:>8} | {:>8} | {:>8} | {:>8} || {:>8} | {:>8} | {:>8} | {:>8}",
            "", "Enc(ms)", "Puz(ms)", "Dec(ms)", "Size", "Enc(ms)", "Puz(ms)", "Dec(ms)", "Size"
        );
        println!("{}", "-".repeat(100));

        for (std, hyb) in &results {
            assert_eq!(std.message_len, hyb.message_len);

            println!(
            "{:<8} | {:>8.2} | {:>8.2} | {:>8.2} | {:>8} || {:>8.2} | {:>8.2} | {:>8.2} | {:>8}",
            std.message_len,
            std.encryption_time.as_secs_f64() * 1000.0,
            std.puzzle_time.as_secs_f64() * 1000.0,
            std.decryption_time.as_secs_f64() * 1000.0,
            std.ciphertext_size,
            hyb.encryption_time.as_secs_f64() * 1000.0,
            hyb.puzzle_time.as_secs_f64() * 1000.0,
            hyb.decryption_time.as_secs_f64() * 1000.0,
            hyb.ciphertext_size
        );
        }
    }
}
