mod chip;
mod circuit;
mod config;
mod instructions;
mod key;

pub use chip::*;
pub use circuit::*;
pub use config::*;
pub use instructions::*;
pub use key::*;

use crate::MAX_SEQUENCER_NUMBER;
use big_integer::*;
use ff::PrimeField;
use halo2wrong::halo2::circuit::Value;

/// Aggregate public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct AggregatePublicParams<F: PrimeField> {
    /// a modulus parameter
    pub n: UnassignedInteger<F>,
    pub n_square: UnassignedInteger<F>,
}

impl<F: PrimeField> AggregatePublicParams<F> {
    /// Creates new [`AggregatePublicParams`] from `n`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    ///
    /// # Return values
    /// Returns new [`AggregatePublicParams`].
    pub fn new(n: UnassignedInteger<F>, n_square: UnassignedInteger<F>) -> Self {
        Self { n, n_square }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let n = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let num_limb2 = num_limbs * 2;
        let n_square = UnassignedInteger {
            value: Value::unknown(),
            num_limbs: num_limb2,
        };
        Self { n, n_square }
    }
}

/// An assigned Aggregate public key.
#[derive(Clone, Debug)]
pub struct AssignedAggregatePublicParams<F: PrimeField> {
    /// a modulus parameter
    pub n: AssignedInteger<F, Fresh>,
    pub n_square: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedAggregatePublicParams<F> {
    /// Creates new [`AssignedAggregatePublicParams`] from assigned `n`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    ///
    /// # Return values
    /// Returns new [`AssignedAggregatePublicParams`].
    pub fn new(n: AssignedInteger<F, Fresh>, n_square: AssignedInteger<F, Fresh>) -> Self {
        Self { n, n_square }
    }
}
