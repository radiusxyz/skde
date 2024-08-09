use std::{str::FromStr, time::Instant};

use delay_encryption::{decrypt, encrypt, solve_time_lock_puzzle, PublicKey};
use key_aggregation::aggregate_key;
use key_generation::{
    generate_partial_key, prove_partial_key_validity, verify_partial_key_validity,
};
use num_bigint::BigUint;
use skde::*;

fn main() {
    let time = 2_u32.pow(TIME_PARAM_T);
    let p = BigUint::from_str(PRIME_P).expect("Invalid PRIME_P");
    let q = BigUint::from_str(PRIME_Q).expect("Invalid PRIME_Q");
    let g = BigUint::from_str(GENERATOR).expect("Invalid GENERATOR");
    let max_sequencer_number = BigUint::from(MAX_SEQUENCER_NUMBER);

    let skde_params = setup(time, p, q, g, max_sequencer_number);
    let message: &str = "12345";

    // 1. Generate partial keys and proofs
    let generated_keys_and_proofs: Vec<_> = (0..MAX_SEQUENCER_NUMBER)
        .enumerate()
        .map(|(index, _)| {
            let start = Instant::now();
            let (secret_value, extraction_key) = generate_partial_key(&skde_params);
            let key_proof = prove_partial_key_validity(&skde_params, &secret_value);
            let generation_duration = start.elapsed();
            println!(
                "Sequencer{}'s key and proof generation time: {:?}",
                index + 1,
                generation_duration
            );
            (extraction_key, key_proof)
        })
        .collect();

    // 2. Verify all generated keys
    let verification_start = Instant::now();
    generated_keys_and_proofs
        .iter()
        .for_each(|(extraction_key, key_proof)| {
            assert!(
                verify_partial_key_validity(
                    &skde_params,
                    extraction_key.clone(),
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
