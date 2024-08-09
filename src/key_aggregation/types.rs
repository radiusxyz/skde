use big_integer::{AssignedInteger, Fresh};
use ff::PrimeField;
use maingate::decompose_big;
use num_bigint::BigUint;

use crate::key_generation::{AssignedPartialKey, UnassignedPartialKey};

#[derive(Debug, Clone)]
pub struct AggregatedKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}
impl AggregatedKey {
    pub fn decompose_partial_key<F: PrimeField>(
        partial_key: &AggregatedKey,
        limb_width: usize,
        limb_count: usize,
    ) -> DecomposedAggregatedKey<F> {
        DecomposedAggregatedKey {
            u_limbs: decompose_big::<F>(partial_key.u.clone(), limb_count, limb_width),
            v_limbs: decompose_big::<F>(partial_key.v.clone(), limb_count * 2, limb_width),
            y_limbs: decompose_big::<F>(partial_key.y.clone(), limb_count, limb_width),
            w_limbs: decompose_big::<F>(partial_key.w.clone(), limb_count * 2, limb_width),
        }
    }
}

/// An assigned AggregateWithHash extraction key.
#[derive(Clone, Debug)]
pub struct AssignedAggregatedKey<F: PrimeField> {
    pub u: AssignedInteger<F, Fresh>,
    pub v: AssignedInteger<F, Fresh>,
    pub y: AssignedInteger<F, Fresh>,
    pub w: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedAggregatedKey<F> {
    pub fn new(
        u: AssignedInteger<F, Fresh>,
        v: AssignedInteger<F, Fresh>,
        y: AssignedInteger<F, Fresh>,
        w: AssignedInteger<F, Fresh>,
    ) -> Self {
        Self { u, v, y, w }
    }
}

#[derive(Clone, Debug)]
pub struct DecomposedAggregatedKey<F: PrimeField> {
    pub u_limbs: Vec<F>,
    pub v_limbs: Vec<F>,
    pub y_limbs: Vec<F>,
    pub w_limbs: Vec<F>,
}

impl<F: PrimeField> DecomposedAggregatedKey<F> {
    pub fn combine_limbs(self) -> Vec<F> {
        let mut combined = Vec::new();

        combined.extend(self.u_limbs);
        combined.extend(self.v_limbs);
        combined.extend(self.y_limbs);
        combined.extend(self.w_limbs);

        combined
    }
}

#[derive(Clone, Debug)]
pub struct UnassignedExtractionKey<F: PrimeField> {
    pub partial_key_list: Vec<UnassignedPartialKey<F>>,
}

impl<F: PrimeField> UnassignedExtractionKey<F> {
    pub fn without_witness(num_limbs: usize, max_sequencer_number: usize) -> Self {
        let mut partial_key_list = vec![];

        for _ in 0..max_sequencer_number {
            partial_key_list.push(UnassignedPartialKey::without_witness(num_limbs));
        }

        Self { partial_key_list }
    }
}

/// Assigned AggregateWithHash partial keys.
#[derive(Clone, Debug)]
pub struct AssignedExtractionKey<F: PrimeField> {
    pub partial_key_list: Vec<AssignedPartialKey<F>>,
}