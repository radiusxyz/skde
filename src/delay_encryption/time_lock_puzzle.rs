use std::io::{self, ErrorKind};

use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod, can_be_divided};
use num_bigint::BigUint;
use num_traits::{Num, One};

use super::SecretKey;
use crate::{key_aggregation::AggregatedKey, SkdeParams};

/// Solves the time-lock puzzle from the SKDE protocol and recovers the
/// SecretKey.
///
/// # Parameters
/// - `skde_params`: Public parameters containing modulus `n`, delay `t`, etc.
/// - `aggregated_key`: Aggregated key (`u`, `v`, `y`, `w`) used to compute the
///   secret key
///
/// # Returns
/// - `Ok(SecretKey)` if the puzzle is solved correctly
/// - `Err(io::Error)` if the result is not divisible by `n` (unexpected
///   failure)
///
/// # Mathematical Summary
/// The SKDE time-lock puzzle computes:
///   sk = [(v * w * (x^n)^(-1) mod n^2) - 1] / n
/// where:
///   - x = (u * y)^T mod n
///   - T = 2^t is the time-lock delay parameter
///   - all operations are in modular arithmetic (mod n or mod n^2)
pub fn solve_time_lock_puzzle(
    skde_params: &SkdeParams,
    aggregated_key: &AggregatedKey,
) -> io::Result<SecretKey> {
    // Parse input parameters
    let n = BigUint::from_str_radix(&skde_params.n, 10).unwrap();
    let n_square: BigUint = &n * &n;
    let time: BigUint = BigUint::from(2u32).pow(skde_params.t);

    let u = BigUint::from_str_radix(&aggregated_key.u, 10).unwrap();
    let y = BigUint::from_str_radix(&aggregated_key.y, 10).unwrap();
    let v = BigUint::from_str_radix(&aggregated_key.v, 10).unwrap();
    let w = BigUint::from_str_radix(&aggregated_key.w, 10).unwrap();

    let one_big = BigUint::one();

    // Step 1: Compute u' = (u * y) mod n
    let u_prime = big_mul_mod(&u, &y, &n);

    // Step 2: Compute v' = (v * w) mod n^2
    let v_prime = big_mul_mod(&v, &w, &n_square);

    // Step 3: Compute x = (u')^T mod n
    let x = big_pow_mod(&u_prime, &time, &n);

    // Step 4: Compute x^n mod n^2
    let x_pow_n = big_pow_mod(&x, &n, &n_square);

    // Step 5: Compute (x^n)^(-1) mod n^2
    let x_pow_n_inv = match big_mod_inv(&x_pow_n, &n_square) {
        Some(inv) => inv,
        None => {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Modular inverse does not exist",
            ));
        }
    };

    // Step 6: Compute final result: ((v' * x_pow_n_inv) mod n^2 - 1) / n
    let combined = big_mul_mod(&v_prime, &x_pow_n_inv, &n_square);
    let result = &combined - &one_big;

    // Step 7: Check divisibility and derive secret key
    if can_be_divided(&result, &n) {
        Ok(SecretKey {
            sk: (result / &n).to_str_radix(10),
        })
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            "Result is not divisible by n",
        ))
    }
}
