use std::{
    io::{self, ErrorKind},
    str::FromStr,
};

use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use super::{
    big_mod_inv, big_mul_mod, big_pow_mod, is_divided, CipherPair, ExtractionKey, PublicKey,
    SecretKey, SingleKeyDelayEncryptionParam,
};

pub fn encrypt(
    skde_params: &SingleKeyDelayEncryptionParam,
    message: &str,
    key: &PublicKey,
) -> io::Result<CipherPair> {
    // TODO: Arbitrary Length of Message
    let plain_text = BigUint::from_str(message).expect("Invalid message");

    if plain_text >= skde_params.n {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Message must be less than modular size",
        ));
    }

    let mut rng = thread_rng();

    // choose a random which is less than N/2
    let l: BigUint = rng.gen_biguint(skde_params.n.bits() / 2);
    let pk_pow_l = big_pow_mod(&key.pk, &l, &skde_params.n);
    let cipher1 = big_pow_mod(&skde_params.g, &l, &skde_params.n);
    let cipher2 = big_mul_mod(&plain_text, &pk_pow_l, &skde_params.n);

    Ok(CipherPair {
        c1: cipher1.to_str_radix(10),
        c2: cipher2.to_str_radix(10),
    })
}

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

    if is_divided(&result, &skde_params.n) {
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

pub fn decrypt(
    skde_params: &SingleKeyDelayEncryptionParam,
    cipher_text: &CipherPair,
    secret_key: &SecretKey,
) -> io::Result<String> {
    let cipher1 = BigUint::from_str(&cipher_text.c1).unwrap();
    let cipher2 = BigUint::from_str(&cipher_text.c2).unwrap();

    let exponentiation = big_pow_mod(&cipher1, &secret_key.sk, &skde_params.n);

    let inv_mod = big_mod_inv(&exponentiation, &skde_params.n)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No modular inverse found"))?;
    let result = (cipher2 * inv_mod) % &skde_params.n;

    Ok(result.to_str_radix(10))
}
