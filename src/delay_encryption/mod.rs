use std::{
    io::{self, ErrorKind},
    ops::{Div, Mul, Rem, Sub},
    str::FromStr,
};

use num_bigint::{BigInt, BigUint, RandBigInt};
use rand::thread_rng;
use sha2::{Digest, Sha512};

pub const MAX_SEQUENCER_NUMBER: usize = 2;

// p * q = 109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129
pub const PRIME_P: &str = "8155133734070055735139271277173718200941522166153710213522626777763679009805792017274916613411023848268056376687809186180768200590914945958831360737612803";
pub const PRIME_Q: &str = "13379153270147861840625872456862185586039997603014979833900847304743997773803109864546170215161716700184487787472783869920830925415022501258643369350348243";
pub const GENERATOR: &str = "4";
pub const TIME_PARAM_T: u32 = 4;

#[derive(Debug, Clone)]
pub struct ExtractionKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub pk: BigUint,
}

#[derive(Debug, Clone)]
pub struct SecretKey {
    pub sk: BigUint,
}

#[derive(Debug, Clone)]
pub struct CipherPair {
    pub c1: String,
    pub c2: String,
}

#[derive(Debug, Clone)]
pub struct SingleKeyDelayEncryptionParam {
    pub n: BigUint, // RSA modulus n = p * q
    pub g: BigUint, // group generator
    pub t: u32,     // delay parameter
    pub h: BigUint, // g^{2^t} mod n
}

#[derive(Debug, Clone)]
pub struct UVPair {
    u: BigUint,
    v: BigUint,
}

#[derive(Debug, Clone)]
pub struct KeyProof {
    a: BigUint,
    b: BigUint,
    tau: BigUint,
    alpha: BigUint,
    beta: BigUint,
}

// compute h = g^{2^t} mod n
fn repeat_square_mod(g: &BigUint, t: u32, n: &BigUint) -> BigUint {
    let mut h = g.clone();
    (0..t).for_each(|_| {
        h = (&h * &h) % n;
    });
    h
}

// compute big integer g^t mod n
fn big_pow_mod(g: &BigUint, t: &BigUint, n: &BigUint) -> BigUint {
    g.modpow(t, n)
}

// compute big integer a * b mod n
fn big_mul_mod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a * b) % modulus
}

fn is_divided(dividend: &BigUint, divisor: &BigUint) -> bool {
    let zero_big = BigUint::from(0u32);
    if divisor == &zero_big {
        return false;
    }

    dividend % divisor == zero_big
}

fn generate_random_biguint(bits_size: u64) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint(bits_size)
}

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

    let lambda = n.bits() / 2 + 1;
    let one_big = BigUint::from(1u32);
    let n_square = n * n;
    let n_plus_one = n + one_big;

    // U = g^r mod n
    let u = big_pow_mod(&g, &a, &n);
    // h_exp_r = h^r mod n, h_exp_rn = h^(r * n) mod n^2
    let h_exp_a = big_pow_mod(&h, &a, &n);
    let h_exp_an = big_pow_mod(&h_exp_a, &n, &n_square);
    // V = (n+1)^s * hrn mod n^2
    let v = (&big_pow_mod(&n_plus_one, &b, &n_square) * &h_exp_an) % &n_square;

    UVPair {
        u: u,
        v: v, // u: pad_or_trim(u, (2 * lambda / 8) as usize),
              // v: pad_or_trim(v, (2 * lambda / 4) as usize),
    }
}

fn big_mod_inv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let mut m0: BigInt = m.clone().into();
    let mut a0: BigInt = a.clone().into();
    let m_int: BigInt = m.clone().into();
    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let mut x0: BigInt = zero.clone().into();
    let mut inv: BigInt = one.clone().into();

    if m == &one {
        return Some(zero);
    }

    while a0 > one.clone().into() {
        let q: BigInt = (a0.clone() / m0.clone()).into();

        let mut temp: BigInt = m0.clone();

        m0 = a0.clone() % m0.clone();
        a0 = temp;

        temp = x0.clone();

        // Update x0 and inv
        x0 = inv.clone() - q.clone() * x0;
        inv = temp;
    }

    // Make inv positive
    if inv < zero.into() {
        inv = inv + m_int;
    }
    inv.to_biguint()
}

fn prove_key_validity(
    skde_params: &SingleKeyDelayEncryptionParam,
    r: &BigUint,
    s: &BigUint,
    k: &BigUint,
) -> KeyProof {
    let m = MAX_SEQUENCER_NUMBER;
    let two_big = BigUint::from(2u32);
    let t = BigUint::from(skde_params.t.clone());
    let n_half = &skde_params.n / &two_big;
    let n_half_plus_n_over_m = &n_half + (&skde_params.n / m);

    let x = generate_random_biguint(n_half_plus_n_over_m.bits());
    let l = generate_random_biguint(n_half.bits());

    let ab_pair = generate_uv_pair(&x, &l, &skde_params);
    let a = ab_pair.u;
    let b = ab_pair.v;
    let tau = big_pow_mod(&skde_params.g, &l, &skde_params.n);

    // Calculate SHA-512 hash
    let transcript = vec![
        &skde_params.n,
        &skde_params.g,
        &t,
        &skde_params.h,
        &a,
        &b,
        &tau,
    ];

    let e = calculate_challenge(&transcript);

    let alpha = (r + s + k) * &e + &x;
    let beta = (r + s) * &e + &l;

    KeyProof {
        a,
        b,
        tau,
        alpha,
        beta,
    }
}

fn calculate_challenge(values: &[&BigUint]) -> BigUint {
    let mut sha = Sha512::new();
    for value in values {
        sha.update(&value.to_bytes_be());
    }
    let hash = sha.finalize();
    BigUint::from_bytes_be(&hash)
}

pub fn setup(t: u32) -> SingleKeyDelayEncryptionParam {
    let p = BigUint::from_str(PRIME_P).expect("Invalid PRIME_P");
    let q = BigUint::from_str(PRIME_Q).expect("Invalid PRIME_Q");
    let g = BigUint::from_str(GENERATOR).expect("Invalid GENERATOR");

    let n = p * q;
    // println!("n = {:?}", n);

    let h = repeat_square_mod(&g, t, &n);

    SingleKeyDelayEncryptionParam { n, g, t, h }
}

pub fn key_generation_with_proof(
    skde_params: SingleKeyDelayEncryptionParam,
) -> (ExtractionKey, KeyProof) {
    let two_big: BigUint = BigUint::from(2u32);

    let n_half: BigUint = &skde_params.n / two_big;
    // let n_over_m: BigUint = &n / m;
    let n_half_over_m: BigUint = &n_half / MAX_SEQUENCER_NUMBER;

    let r = generate_random_biguint(n_half_over_m.bits());
    let s = generate_random_biguint(n_half_over_m.bits());
    let k = generate_random_biguint(n_half.bits());

    let uv_pair = generate_uv_pair(&(&r + &s), &s, &skde_params);
    let yw_pair = generate_uv_pair(&k, &r, &skde_params);

    // proof generation for validity for the key pairs

    // TODO: Range proof generation using SNARK
    let key_proof = prove_key_validity(&skde_params, &r, &s, &k);

    (
        ExtractionKey {
            u: uv_pair.u,
            v: uv_pair.v,
            y: yw_pair.u,
            w: yw_pair.v,
        },
        key_proof,
    )
}

fn verify_key_validity(
    skde_params: &SingleKeyDelayEncryptionParam,
    extraction_key: ExtractionKey,
    key_proof: KeyProof,
) -> bool {
    let t = BigUint::from(skde_params.t.clone());
    let n_square: BigUint = &skde_params.n * &skde_params.n;

    let one_big = BigUint::from(1u32);

    let a: BigUint = key_proof.a;
    let b: BigUint = key_proof.b;
    let tau: BigUint = key_proof.tau;
    let alpha: BigUint = key_proof.alpha;
    let beta: BigUint = key_proof.beta;

    let u = &extraction_key.u;
    let v = &extraction_key.v;
    let y = &extraction_key.y;
    let w = &extraction_key.w;

    // TODO: Range proof verification using SNARK

    // Calculate SHA-512 hash
    let transcript = vec![
        &skde_params.n,
        &skde_params.g,
        &t,
        &skde_params.h,
        &a,
        &b,
        &tau,
    ];

    let e = calculate_challenge(&transcript);

    let h_exp_nalpha = big_pow_mod(&skde_params.h, &(&alpha * &skde_params.n), &n_square);
    let n_plus_one_exp_beta = big_pow_mod(&(&skde_params.n + &one_big), &beta, &n_square);

    let lhs = vec![
        big_pow_mod(&skde_params.g, &alpha, &skde_params.n),
        big_mul_mod(&h_exp_nalpha, &n_plus_one_exp_beta, &n_square),
        big_pow_mod(&skde_params.g, &beta, &skde_params.n),
    ];

    let uy = big_mul_mod(u, y, &skde_params.n);
    let vw = big_mul_mod(v, w, &n_square);

    let rhs = vec![
        big_mul_mod(&big_pow_mod(&uy, &e, &skde_params.n), &a, &skde_params.n),
        big_mul_mod(&big_pow_mod(&vw, &e, &n_square), &b, &n_square),
        big_mul_mod(&big_pow_mod(u, &e, &skde_params.n), &tau, &skde_params.n),
    ];

    // println!("lhs: {:?}", lhs);
    // println!("rhs: {:?}", rhs);
    let verified = lhs.iter().zip(rhs.iter()).all(|(l, r)| l == r);

    // println!(
    //     "Are all corresponding elements in lhs and rhs equal? {}",
    //     verified
    // );

    verified
}

pub fn aggregate_key_pairs(
    key_pairs: &[ExtractionKey],
    skde_params: &SingleKeyDelayEncryptionParam,
) -> ExtractionKey {
    let n_square = &skde_params.n * &skde_params.n;
    let mut aggregated_u = BigUint::from(1u32);
    let mut aggregated_v = BigUint::from(1u32);
    let mut aggregated_y = BigUint::from(1u32);
    let mut aggregated_w = BigUint::from(1u32);
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

pub fn encrypt(
    skde_params: &SingleKeyDelayEncryptionParam,
    message: &str,
    key: &PublicKey,
) -> io::Result<CipherPair> {
    // TODO: Arbitrary Length of Message
    let plain_text = BigUint::from_str(message).expect("Invalid message");
    if plain_text >= skde_params.n {
        // std::io::Error
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
    let t = BigUint::from(skde_params.t.clone());
    let time: BigUint = BigUint::from(2u32).modpow(&t, &skde_params.n);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn setup_test() {
        setup(200);
    }

    #[test]
    fn test_signle_key_delay_encryption() {
        let skde_params = setup(TIME_PARAM_T);
        let mut key_pairs: Vec<ExtractionKey> = Vec::new();
        let message: &str = "12345";

        for _ in 0..MAX_SEQUENCER_NUMBER {
            let (extraction_key, key_proof) = key_generation_with_proof(skde_params.clone());
            assert!(
                verify_key_validity(&skde_params, extraction_key.clone(), key_proof),
                "Key verification failed"
            );
            key_pairs.push(extraction_key);
        }
        // Aggregate all generated keys
        let aggregated_key = aggregate_key_pairs(&key_pairs, &skde_params);
        println!("aggregated key: {:?}", aggregated_key);

        let public_key = PublicKey {
            pk: aggregated_key.u.clone(),
        };

        let secret_key = solve_time_lock_puzzle(&skde_params, &aggregated_key).unwrap();

        println!("Puzzle solved!: {:?}", secret_key);

        let cipher_text = encrypt(&skde_params, message, &public_key).unwrap();

        println!("Encryption Result: {:?}", cipher_text);

        let decrypted_message = decrypt(&skde_params, &cipher_text, &secret_key).unwrap();

        println!("decrypted_message: {:?}", decrypted_message);

        assert_eq!(
            message, decrypted_message,
            "Decrypted message does not same with the original message"
        );
    }
}
