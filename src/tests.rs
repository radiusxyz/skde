#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Instant};

    use big_integer::mod_exp_by_pow_of_two;
    use num_bigint::BigUint;
    use rand::{distributions::Alphanumeric, Rng};

    use crate::{
        delay_encryption::{
            decrypt, encrypt, setup, solve_time_lock_puzzle, validate_secret_key, SkdeParams,
        },
        key_aggregation::aggregate_key,
        key_generation::{
            generate_partial_key, prove_partial_key_validity,
            range_proof::{
                generate_range_proof, verify_proofs, verify_proofs_parallel, verify_range_proof,
                RangeProofInput, BASE, EXPONENT, MODULUS, RANGE,
            },
            verify_partial_key_validity,
        },
        BIT_LEN, GENERATOR, MAX_SEQUENCER_NUMBER, TIME_PARAM_T,
    };

    // Predefined RSA modulus for deterministic encryption test
    pub const MOD_N: &str = "26737688233630987849749538623559587294088037102809480632570023773459222152686633609232230584184543857897813615355225270819491245893096628373370101798393754657209853664433779631579690734503677773804892912774381357280025811519740953667880409246987453978226997595139808445552217486225687511164958368488319372068289768937729234964502681229612929764203977349037219047813560623373035187038018937232123821089208711930458219009895581132844064176371047461419609098259825422421077554570457718558971463292559934623518074946858187287041522976374186587813034651849410990884606427758413847140243755163116582922090226726575253150079";

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

    fn setup_default_input() -> RangeProofInput {
        RangeProofInput::new(
            BigUint::from_str(BASE).expect("Invalid number for Base"),
            BigUint::from_str(MODULUS).expect("Invalid number for Modulus"),
            BigUint::from_str(EXPONENT).expect("Invalid number for Exponent"),
            BigUint::from_str(RANGE).expect("Invalid number for Range"),
        )
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

    fn run_encryption_benchmark(
        hybrid: bool,
        message_len: usize,
        generate_range_proofs: bool,
    ) -> BenchmarkResult {
        // Set skde parameters
        let skde_params = default_skde_params();
        let message = generate_random_message(message_len);

        // Generate partial keys & Verify all
        let partial_keys: Vec<_> = (0..MAX_SEQUENCER_NUMBER)
            .map(|_| {
                let (secret, partial) = generate_partial_key(&skde_params).unwrap();
                let proof = prove_partial_key_validity(&skde_params, &secret).unwrap();
                assert!(verify_partial_key_validity(&skde_params, partial.clone(), proof).unwrap());

                if generate_range_proofs {
                    println!("Generating range proof for partial key: {}", partial.u);
                    let range_proof = generate_range_proof(&RangeProofInput::new(
                        BigUint::from_str(&skde_params.g).unwrap(),
                        BigUint::from_str(&skde_params.n).unwrap(),
                        secret.r + secret.s,
                        BigUint::from_str(RANGE).unwrap(),
                    ))
                    .unwrap();
                    verify_range_proof(partial.u.clone(), &range_proof.receipt).unwrap();
                }

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
            encryption_time,
            puzzle_time,
            decryption_time,
            ciphertext_size,
        }
    }

    fn print_benchmark_results(results: &[(BenchmarkResult, BenchmarkResult)], title: &str) {
        println!("\n=== Benchmark Results {} ===", title);
        println!("{:<8} | {:^41} || {:^41}", "Bytes", "Standard", "Hybrid");
        println!("{}", "-".repeat(100));
        println!(
            "{:<8} | {:>8} | {:>8} | {:>8} | {:>8} || {:>8} | {:>8} | {:>8} | {:>8}",
            "", "Enc(ms)", "Puz(ms)", "Dec(ms)", "Size", "Enc(ms)", "Puz(ms)", "Dec(ms)", "Size"
        );
        println!("{}", "-".repeat(100));

        for (std, hyb) in results {
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

    #[test]
    fn test_range_proof_single_generate_and_verify() {
        // Test small bits
        let exponent = BigUint::from_str(EXPONENT).expect("Invalid number for Exponent");

        let input = RangeProofInput {
            base: BigUint::from_str("4").unwrap(),
            modulus: BigUint::from_str("6").unwrap(),
            exponent: BigUint::from_str("5").unwrap(),
            range: BigUint::from_str(RANGE).expect("Invalid number for Range"),
        };
        let proof = generate_range_proof(&input).unwrap();
        let u = input.base.modpow(&exponent, &input.modulus);
        verify_range_proof(u, &proof.receipt).unwrap();

        // Test 2048-bits
        let input = setup_default_input();
        let proof = generate_range_proof(&input).unwrap();
        let u = input.base.modpow(&exponent, &input.modulus);
        verify_range_proof(u, &proof.receipt).unwrap();
    }

    #[test]
    fn test_range_proof_verification_benchmark() {
        let exponent = BigUint::from_str(EXPONENT).expect("Invalid number for Exponent");
        let num_proofs = 32;

        // Creating proofs with small bit size input
        let input = RangeProofInput {
            base: BigUint::from_str("4").unwrap(),
            modulus: BigUint::from_str("6").unwrap(),
            exponent: exponent.clone(),
            range: BigUint::from_str(RANGE).expect("Invalid number for Range"),
        };

        println!("Number of proofs to generate: {}", num_proofs);
        println!("Generating proofs...");

        // Create identical proofs
        let mut receipts = Vec::with_capacity(num_proofs);
        let mut u_vec = Vec::with_capacity(num_proofs);
        let proof = generate_range_proof(&input).unwrap();
        let u = input.base.modpow(&exponent, &input.modulus);

        for _i in 0..num_proofs {
            receipts.push(proof.receipt.clone());
            u_vec.push(u.clone());
        }

        // Measure sequential verification time
        println!("\n=== Sequential Verification Start ===");
        let sequential_start = Instant::now();
        verify_proofs(u_vec.clone(), &receipts).unwrap();
        let sequential_duration = sequential_start.elapsed();

        // Measure parallel verification time
        println!("\n=== Parallel Verification Start ===");
        let parallel_start = Instant::now();
        verify_proofs_parallel(u_vec.clone(), &receipts).unwrap();
        let parallel_duration = parallel_start.elapsed();

        // Print comparison results
        println!("\n=== Performance Comparison Results ===");
        println!("Sequential verification time: {:?}", sequential_duration);
        println!("Parallel verification time: {:?}", parallel_duration);

        if parallel_duration < sequential_duration {
            let speedup = sequential_duration.as_secs_f64() / parallel_duration.as_secs_f64();
            println!("Parallel processing is {:.2}x faster", speedup);
        } else {
            let slowdown = parallel_duration.as_secs_f64() / sequential_duration.as_secs_f64();
            println!("Sequential processing is {:.2}x faster", slowdown);
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
        println!("{:?}", n.bits());
        assert!(n.bits() >= (BIT_LEN - 1) as u64, "Modulus too small");
    }

    #[test]
    fn test_encryption_benchmark_standard_vs_hybrid_without_range_proofs() {
        let mut results: Vec<(BenchmarkResult, BenchmarkResult)> = Vec::new();

        println!("Running benchmarks WITHOUT range proofs");
        for &len in &[64, 128, 256, 512, 1024, 2048] {
            let standard = run_encryption_benchmark(false, len, false);
            let hybrid = run_encryption_benchmark(true, len, false);
            results.push((standard, hybrid));
        }

        print_benchmark_results(&results, "WITHOUT Range Proofs");
    }

    #[test]
    #[ignore]
    fn test_encryption_benchmark_standard_vs_hybrid_with_range_proofs() {
        let mut results: Vec<(BenchmarkResult, BenchmarkResult)> = Vec::new();

        println!("Running benchmarks WITH range proofs");
        for &len in &[64, 128, 256, 512, 1024, 2048] {
            let standard = run_encryption_benchmark(false, len, true);
            let hybrid = run_encryption_benchmark(true, len, true);
            results.push((standard, hybrid));
        }

        print_benchmark_results(&results, "WITH Range Proofs");
    }

    #[test]
    fn test_secret_key_validation() {
        // 1. Set up SKDE parameters
        let skde_params = default_skde_params();

        // 2. Generate partial keys and verify
        let partial_keys: Vec<_> = (0..MAX_SEQUENCER_NUMBER)
            .map(|_| {
                let (secret, partial) = generate_partial_key(&skde_params).unwrap();
                let proof = prove_partial_key_validity(&skde_params, &secret).unwrap();
                assert!(verify_partial_key_validity(&skde_params, partial.clone(), proof).unwrap());
                partial
            })
            .collect();

        // 3. Aggregate public keys and solve puzzle
        let aggregated_key = aggregate_key(&skde_params, &partial_keys);
        let encryption_key = aggregated_key.u.clone();
        let secret_key =
            solve_time_lock_puzzle(&skde_params, &aggregated_key).expect("Puzzle solving failed");

        // 4. Validate the secret key
        let is_valid = validate_secret_key(&skde_params, &encryption_key, &secret_key.sk, true);

        assert!(is_valid, "Secret key validation failed");
    }
}
