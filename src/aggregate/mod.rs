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

use big_integer::UnassignedInteger;
use big_integer::*;
use ff::PrimeField;
use halo2wrong::halo2::circuit::Value;

use crate::MAX_SEQUENCER_NUMBER;

/// Public Parameters that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedAggregatePublicParams<F: PrimeField> {
    pub n: UnassignedInteger<F>,
    pub n_square: UnassignedInteger<F>,
}

impl<F: PrimeField> UnassignedAggregatePublicParams<F> {
    pub fn without_witness(num_limbs: usize) -> Self {
        Self {
            n: UnassignedInteger::new(Value::unknown(), num_limbs),
            n_square: UnassignedInteger::new(Value::unknown(), num_limbs * 2),
        }
    }
}

/// Assigned AggregateWithHash public params.
#[derive(Clone, Debug)]
pub struct AssignedAggregatePublicParams<F: PrimeField> {
    pub n: AssignedInteger<F, Fresh>,
    pub n_square: AssignedInteger<F, Fresh>,
}
