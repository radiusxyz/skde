use super::{CipherPair, PublicKey, SecretKey};
use crate::SkdeParams;
use big_integer::{big_mod_inv, big_mul_mod, big_pow_mod};
use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;
use rand::thread_rng;
use std::{
    io::{self, ErrorKind},
    str::FromStr,
};

pub fn encrypt(
    skde_params: &SkdeParams,
    message: &str,
    encryption_key: &PublicKey,
    radix: u32,
) -> io::Result<CipherPair> {
    // TODO: Arbitrary Length of Message
    let plain_text;
    if message.starts_with("0x") {
        plain_text = BigUint::from_str_radix(&message[2..], radix).expect("Invalid message");
    } else {
        plain_text = BigUint::from_str_radix(message, radix).expect("Invalid message");
    }

    if plain_text >= skde_params.n {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Message must be less than modular size",
        ));
    }

    let mut rng = thread_rng();

    // choose a random which is less than N/2
    let l: BigUint = rng.gen_biguint(skde_params.n.bits() / 2);
    let pk_pow_l = big_pow_mod(&encryption_key.pk, &l, &skde_params.n);
    let cipher1 = big_pow_mod(&skde_params.g, &l, &skde_params.n);
    let cipher2 = big_mul_mod(&plain_text, &pk_pow_l, &skde_params.n);

    Ok(CipherPair {
        c1: cipher1.to_str_radix(10),
        c2: cipher2.to_str_radix(10),
    })
}

pub fn decrypt(
    skde_params: &SkdeParams,
    cipher_text: &CipherPair,
    decryption_key: &SecretKey,
    radix: u32,
) -> io::Result<String> {
    let cipher1 = BigUint::from_str(&cipher_text.c1).unwrap();
    let cipher2 = BigUint::from_str(&cipher_text.c2).unwrap();

    let exponentiation = big_pow_mod(&cipher1, &decryption_key.sk, &skde_params.n);

    let inv_mod = big_mod_inv(&exponentiation, &skde_params.n)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No modular inverse found"))?;

    let result = (cipher2 * inv_mod) % &skde_params.n;

    Ok(result.to_str_radix(radix))
}
