use ff::PrimeField;

use super::{AssignedExtractionKey, UnassignedExtractionKey};

/// An assigned Aggregate public key.
#[derive(Clone, Debug)]
pub struct AssignedAggregatePartialKeys<F: PrimeField> {
    pub partial_keys: Vec<AssignedExtractionKey<F>>,
}

/// Aggregate public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedAggregatePartialKeys<F: PrimeField> {
    pub partial_keys: Vec<UnassignedExtractionKey<F>>,
}

impl<F: PrimeField> UnassignedAggregatePartialKeys<F> {
    pub fn without_witness(num_limbs: usize, max_sequencer_number: usize) -> Self {
        let mut partial_keys = vec![];

        for _ in 0..max_sequencer_number {
            partial_keys.push(UnassignedExtractionKey::without_witness(num_limbs));
        }

        Self { partial_keys }
    }
}
