use std::io::{self, ErrorKind};

use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod, can_be_divided};
use num_bigint::BigUint;
use num_traits::{Num, One};

use super::SecretKey;
use crate::{key_aggregation::AggregatedKey, SkdeParams};

pub fn solve_time_lock_puzzle(
    skde_params: &SkdeParams,
    aggregated_key: &AggregatedKey,
) -> io::Result<SecretKey> {
    let n = BigUint::from_str_radix(&skde_params.n, 10).unwrap();

    let u = BigUint::from_str_radix(&aggregated_key.u, 10).unwrap();
    let y = BigUint::from_str_radix(&aggregated_key.y, 10).unwrap();
    let v = BigUint::from_str_radix(&aggregated_key.v, 10).unwrap();
    let w = BigUint::from_str_radix(&aggregated_key.w, 10).unwrap();

    let time: BigUint = BigUint::from(2u32).pow(skde_params.t);

    let one_big = BigUint::one();
    let n_square: BigUint = &n * &n;

    let u_p = big_mul_mod(&u, &y, &n);
    let v_p = big_mul_mod(&v, &w, &n_square);

    let x = big_pow_mod(&u_p, &time, &n);
    let x_pow_n = big_pow_mod(&x, &n, &n_square);
    let x_pow_n_inv = big_mod_inv(&x_pow_n, &n_square).unwrap();

    let result = big_mul_mod(&v_p, &x_pow_n_inv, &n_square);
    let result = result - &one_big;

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
