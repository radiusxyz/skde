use ff::PrimeField;

use crate::key_generation::{AssignedPartialKey, UnassignedPartialKey};

#[derive(Clone, Debug)]
pub struct UnassignedExtractionKey<F: PrimeField> {
    pub partial_keys: Vec<UnassignedPartialKey<F>>,
}

impl<F: PrimeField> UnassignedExtractionKey<F> {
    pub fn without_witness(num_limbs: usize, max_sequencer_number: usize) -> Self {
        let mut partial_keys = vec![];

        for _ in 0..max_sequencer_number {
            partial_keys.push(UnassignedPartialKey::without_witness(num_limbs));
        }

        Self { partial_keys }
    }
}

/// Assigned AggregateWithHash partial keys.
#[derive(Clone, Debug)]
pub struct AssignedExtractionKey<F: PrimeField> {
    pub partial_keys: Vec<AssignedPartialKey<F>>,
}
