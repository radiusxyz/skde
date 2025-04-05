pub use big_integer::generate_random_biguint;
use delay_encryption::SkdeParams;
pub use num_bigint::BigUint;
pub use num_prime::RandPrime;

pub mod delay_encryption;
pub mod key_aggregation;
pub mod key_generation;
pub mod range_proof;
mod tests;

pub const MAX_SEQUENCER_NUMBER: usize = 2;
pub const BIT_LEN: usize = 2048; // n's bit length

pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BIT_LEN / LIMB_WIDTH;

pub const GENERATOR: &str = "4"; // g = 4 is safe as long as gcd(g, n) = 1 (i.e., g is invertible mod n)
pub const TIME_PARAM_T: u32 = 2;
