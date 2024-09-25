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

/* 
TODO: DH
encrypt(
    skde_params: &SkdeParams,
    message: &str, // "안ㄴ녕하세요 저는 한ㅁ니ㅏ어리머니ㅏㅇ러ㅏ미ㅏ넝리ㅓㅁ닝러ㅏㅣㅁㄴ" // "1231" // "0x1111" / "{"from": "0x123", "to": "0x123", "value": 123}"
    encryption_key: &PublicKey,
) -> io::Result<String> // Vec<CipherPair>의 string화

let encrypted_data = format!("{}/{}", encrypted_data.c1, encrypted_data.c2);
let encrypted_data = format!("{},", encrypted_data);

pub fn decrypt(
    skde_params: &SkdeParams,
    encrypted_data: &str,
    decryption_key: &SecretKey,
) -> io::Result<String> {
 
let encrypted_data = format!("{},", encrypted_data);
let encrypted_data = format!("{}/{}", encrypted_data.c1, encrypted_data.c2);

concat

*/
pub fn encrypt(
    skde_params: &SkdeParams,
    message: &str, // "안ㄴ녕하세요 저는 한ㅁ니ㅏ어리머니ㅏㅇ러ㅏ미ㅏ넝리ㅓㅁ닝러ㅏㅣㅁㄴ" // "1231" // "0x1111" / "{"from": "0x123", "to": "0x123", "value": 123}"
    encryption_key: &PublicKey,
) -> io::Result<String> {
    // String -> bytes -> Hex String (어떤수)
    let message_hex_string = string_to_hex(message);

    let plain_text = BigUint::from_str_radix(&message_hex_string, 16).expect("Invalid message");

    // 123123123123123123123234234234234

    // skde_params.n = 12312312312312 -> 14 -> 13
    // 12312312312312 -> encryptedTx
    // 31231232342342 -> encryptedTx
    // 342340x2312323 -> encryptedTx
    // 4234234234     -> encryptedTx
    //-> Vec<CipherPair>

    // TODO: Arbitrary Length of Message
    // TODO: Support for message length greater than N
    if plain_text >= skde_params.n {
        // 어떤수가 길이만큼 잘라야함
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

    Vec<CipherPair>

    Ok(CipherPair {
        c1: cipher1.to_str_radix(10),
        c2: cipher2.to_str_radix(10),
    })
}

// 4234234234     -> //-> Vec<CipherPair>
// 12312312312312 <- encryptedTx
// 31231232342342 <- encryptedTx
// 342340x2312323 <- encryptedTx
// 4234234234     <- encryptedTx
// => // 123123123123123123123234234234234
pub fn decrypt(
    skde_params: &SkdeParams,
    cipher_text_list: &Vec<CipherPair>,
    decryption_key: &SecretKey,
) -> io::Result<String> {
    let mut message_hex_string = String::new();

    for let cipher_text in cipher_text_list {
        let cipher1 = BigUint::from_str(&cipher_text.c1).unwrap();
        let cipher2 = BigUint::from_str(&cipher_text.c2).unwrap();

        let exponentiation = big_pow_mod(&cipher1, &decryption_key.sk, &skde_params.n);

        let inv_mod = big_mod_inv(&exponentiation, &skde_params.n)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No modular inverse found"))?;

        let result = (cipher2 * inv_mod) % &skde_params.n;
        message_hex_string += result.to_str_radix(16);

    }

    // let message = hex_to_string(&message_hex_string).unwrap();

    // let cipher1 = BigUint::from_str(&cipher_text.c1).unwrap();
    // let cipher2 = BigUint::from_str(&cipher_text.c2).unwrap();

    // let exponentiation = big_pow_mod(&cipher1, &decryption_key.sk, &skde_params.n);

    // let inv_mod = big_mod_inv(&exponentiation, &skde_params.n)
    //     .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No modular inverse found"))?;

    // let result = (cipher2 * inv_mod) % &skde_params.n;
    // let message_hex_string = result.to_str_radix(16);

    let message = hex_to_string(&message_hex_string).unwrap();

    Ok(message)
}

fn string_to_hex(s: &str) -> String {
    let vec: Vec<u8> = s.as_bytes().to_vec(); // 문자열을 벡터로 변환
    let hex_string: String = vec.iter().map(|byte| format!("{:02x}", byte)).collect();
    hex_string
}

fn hex_to_string(hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    let result_string = String::from_utf8(bytes)?;
    Ok(result_string)
}
