use num_bigint::BigUint;
// compute big integer g^t mod n
pub fn big_pow_mod(g: &BigUint, t: &BigUint, n: &BigUint) -> BigUint {
    g.modpow(t, n)
}
