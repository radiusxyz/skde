use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

// compute h = g^{2^t} mod n
pub fn pow_mod(g: &BigUint, t: u32, n: &BigUint) -> BigUint {
    let mut h = g.clone();
    (0..t).for_each(|_| {
        h = (&h * &h) % n;
    });
    h
}

// compute big integer g^t mod n
pub fn big_pow_mod(g: &BigUint, t: &BigUint, n: &BigUint) -> BigUint {
    g.modpow(t, n)
}

// compute big integer a * b mod n
pub fn big_mul_mod(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a * b) % modulus
}

pub fn is_divided(dividend: &BigUint, divisor: &BigUint) -> bool {
    if divisor == &BigUint::zero() {
        return false;
    }

    dividend % divisor == BigUint::zero()
}

pub fn generate_random_biguint(bits_size: u64) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint(bits_size)
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
