use ff::PrimeField;

use super::{AssignedExtractionKey, UnassignedExtractionKey};

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

/// Assigned AggregateWithHash partial keys.
#[derive(Clone, Debug)]
pub struct AssignedAggregatePartialKeys<F: PrimeField> {
    pub partial_keys: Vec<AssignedExtractionKey<F>>,
}
