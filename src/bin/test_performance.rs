use std::time::Instant;

use delay_encryption::{
    aggregate_key_pairs, decrypt, encrypt, key_generation_with_proof, setup,
    solve_time_lock_puzzle, verify_key_validity, PublicKey,
};
use skde::*;

fn main() {
    let time = 2_u32.pow(TIME_PARAM_T);
    let skde_params = setup(time);
    let message: &str = "12345";

    let generated_keys_and_proofs: Vec<_> = (0..MAX_SEQUENCER_NUMBER)
        .enumerate()
        .map(|(index, _)| {
            let start = Instant::now();
            let result = key_generation_with_proof(skde_params.clone());
            let generation_duration = start.elapsed();
            println!(
                "Sequencer{}'s key and proof generation time: {:?}",
                index + 1,
                generation_duration
            );
            result
        })
        .collect();

    // verify_key_validity time measure
    let verification_start = Instant::now();
    generated_keys_and_proofs
        .iter()
        .for_each(|(extraction_key, key_proof)| {
            assert!(
                verify_key_validity(&skde_params, extraction_key.clone(), key_proof.clone()),
                "Key verification failed"
            );
        });
    let verification_duration = verification_start.elapsed();

    println!(
        "Total key verification time for {} keys: {:?}",
        MAX_SEQUENCER_NUMBER, verification_duration
    );

    let extraction_keys: Vec<_> = generated_keys_and_proofs
        .into_iter()
        .map(|(extraction_key, _)| extraction_key)
        .collect();

    // Aggregate all generated keys
    let aggregation_start = Instant::now();
    let aggregated_key = aggregate_key_pairs(&extraction_keys, &skde_params);
    let aggregation_duration = aggregation_start.elapsed();
    println!("Aggregation time: {:?}", aggregation_duration);

    let public_key = PublicKey {
        pk: aggregated_key.u.clone(),
    };

    let encryption_start = Instant::now();
    let cipher_text = encrypt(&skde_params, message, &public_key).unwrap();
    let encryption_duration = encryption_start.elapsed();
    println!("Encryption time: {:?}", encryption_duration);

    let puzzle_start = Instant::now();
    let secret_key = solve_time_lock_puzzle(&skde_params, &aggregated_key).unwrap();
    let puzzle_duration = puzzle_start.elapsed();
    println!("Puzzle solved time: {:?}", puzzle_duration);

    let decryption_start = Instant::now();
    let decrypted_message = decrypt(&skde_params, &cipher_text, &secret_key).unwrap();
    let decryption_duration = decryption_start.elapsed();
    println!("Decryption time: {:?}", decryption_duration);

    assert_eq!(
        message, decrypted_message,
        "Decrypted message does not same with the original message"
    );
}
