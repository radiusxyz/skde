mod cryptography;
mod single_key_delay_encryption_zkp;
mod time_lock_puzzle;
mod types;
mod util;

pub use cryptography::*;
pub use single_key_delay_encryption_zkp::*;
pub use time_lock_puzzle::*;
pub use types::*;
pub use util::*;

use num_bigint::BigUint;
use num_traits::One;
use sha2::{Digest, Sha512};

use crate::aggregate::ExtractionKey;

// Input: (a, b, skde_params = (n, g, t, h))
// Output: (u = g^a, v = h^{a * n} * (1 + n)^b)
fn generate_uv_pair(
    a: &BigUint,
    b: &BigUint,
    skde_params: &SingleKeyDelayEncryptionParam,
) -> UVPair {
    let n = &skde_params.n;
    let g = &skde_params.g;
    let h = &skde_params.h;

    // let lambda = n.bits() / 2 + 1;
    let n_square = n * n;
    let n_plus_one = n + BigUint::one();

    // U = g^r mod n
    let u = big_pow_mod(g, a, n);

    // h_exp_r = h^r mod n, h_exp_rn = h^(r * n) mod n^2
    let h_exp_a = big_pow_mod(h, a, n);
    let h_exp_an = big_pow_mod(&h_exp_a, n, &n_square);

    // v = (n+1)^s * hrn mod n^2
    let v = (&big_pow_mod(&n_plus_one, b, &n_square) * &h_exp_an) % &n_square;

    UVPair { u, v }
}

fn calculate_challenge(values: &[&BigUint]) -> BigUint {
    let mut sha = Sha512::new();
    for value in values {
        sha.update(&value.to_bytes_be());
    }
    let hash = sha.finalize();
    BigUint::from_bytes_be(&hash)
}

pub fn aggregate_key_pairs(
    key_pairs: &[ExtractionKey],
    skde_params: &SingleKeyDelayEncryptionParam,
) -> ExtractionKey {
    let n_square = &skde_params.n * &skde_params.n;

    let mut aggregated_u = BigUint::one();
    let mut aggregated_v = BigUint::one();
    let mut aggregated_y = BigUint::one();
    let mut aggregated_w = BigUint::one();

    // Multiply each component of each ExtractionKey in the array
    for key in key_pairs {
        aggregated_u = big_mul_mod(&aggregated_u, &key.u, &skde_params.n);
        aggregated_v = big_mul_mod(&aggregated_v, &key.v, &n_square);
        aggregated_y = big_mul_mod(&aggregated_y, &key.y, &skde_params.n);
        aggregated_w = big_mul_mod(&aggregated_w, &key.w, &n_square);
    }

    // Create a new ExtractionKey instance with the calculated results
    ExtractionKey {
        u: aggregated_u,
        v: aggregated_v,
        y: aggregated_y,
        w: aggregated_w,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::{MAX_SEQUENCER_NUMBER, TIME_PARAM_T};

    use super::*;

    #[test]
    fn test_single_key_delay_encryption() {
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
}
