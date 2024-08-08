use std::io::{self, ErrorKind};

use num_bigint::BigUint;

use super::{
    big_mod_inv, big_mul_mod, big_pow_mod, can_be_divided, ExtractionKey, SecretKey,
    SingleKeyDelayEncryptionParam,
};

pub fn solve_time_lock_puzzle(
    skde_params: &SingleKeyDelayEncryptionParam,
    aggregated_key: &ExtractionKey,
) -> io::Result<SecretKey> {
    let n_square: BigUint = &skde_params.n * &skde_params.n;

    let one_big = BigUint::from(1u32);
    let time: BigUint = BigUint::from(2u32).pow(skde_params.t);

    let u_p = big_mul_mod(&aggregated_key.u, &aggregated_key.y, &skde_params.n);
    let v_p = big_mul_mod(&aggregated_key.v, &aggregated_key.w, &n_square);
    let x = big_pow_mod(&u_p, &time, &skde_params.n);
    let x_pow_n = x.modpow(&skde_params.n, &n_square);
    let x_pow_n_inv = big_mod_inv(&x_pow_n, &n_square).unwrap();
    let result = big_mul_mod(&v_p, &x_pow_n_inv, &n_square);
    let result = result - &one_big;

    if can_be_divided(&result, &skde_params.n) {
        Ok(SecretKey {
            sk: result / &skde_params.n,
        })
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            "Result is not divisible by n",
        ))
    }
}
