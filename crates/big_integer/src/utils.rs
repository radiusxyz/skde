use num_bigint::RandBigInt;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

pub fn generate_random_biguint(modulus: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    let random_biguint = rng.gen_biguint_below(modulus);
    println!("Generated random BigUint: {:?}", random_biguint); // 랜덤 BigUint 값 출력
    random_biguint
}

// compute big integer g^t mod n
pub fn big_pow_mod(g: &BigUint, t: &BigUint, n: &BigUint) -> BigUint {
    g.modpow(t, n)
}

// // compute big integer a * b mod n
pub fn big_mul_mod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a * b) % modulus
}

// compute h = g^{2^t} mod n
pub fn mod_exp_by_pow_of_two(g: &BigUint, t: u32, n: &BigUint) -> BigUint {
    let mut h = g.clone();
    (0..t).for_each(|_| {
        h = (&h * &h) % n;
    });
    h
}

pub fn can_be_divided(dividend: &BigUint, divisor: &BigUint) -> bool {
    if divisor == &BigUint::zero() {
        return false;
    }

    dividend % divisor == BigUint::zero()
}

pub fn big_mod_inv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let one = BigUint::one();
    if m == &one {
        return Some(BigUint::zero());
    }

    let mut m0 = m.to_bigint().unwrap();
    let mut a0 = a.to_bigint().unwrap();
    let m_int = m0.clone();
    let mut x0 = BigInt::zero();
    let mut inv = BigInt::one();

    while a0 > BigInt::one() {
        let q = &a0 / &m0;
        let temp = m0.clone();
        m0 = &a0 % &m0;
        a0 = temp;
        let temp_x0 = x0.clone();
        x0 = inv - &q * x0;
        inv = temp_x0;
    }

    if inv < BigInt::zero() {
        inv += m_int;
    }

    inv.to_biguint()
}
