use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub fn generate_random_biguint(bits_size: u64) -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint(bits_size)
}
