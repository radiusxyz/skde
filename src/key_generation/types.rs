use big_integer::{AssignedInteger, Fresh, UnassignedInteger};
use ff::PrimeField;

use maingate::{decompose_big, halo2::circuit::Value};
use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub struct SecretValue {
    pub r: BigUint,
    pub s: BigUint,
    pub k: BigUint,
}

#[derive(Debug, Clone)]
pub struct PartialKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}

impl PartialKey {
    pub fn decompose_partial_key<F: PrimeField>(
        partial_key: &PartialKey,
        limb_width: usize,
        limb_count: usize,
    ) -> DecomposedPartialKey<F> {
        DecomposedPartialKey {
            u_limbs: decompose_big::<F>(partial_key.u.clone(), limb_count, limb_width),
            v_limbs: decompose_big::<F>(partial_key.v.clone(), limb_count * 2, limb_width),
            y_limbs: decompose_big::<F>(partial_key.y.clone(), limb_count, limb_width),
            w_limbs: decompose_big::<F>(partial_key.w.clone(), limb_count * 2, limb_width),
        }
    }

    pub fn decompose_and_combine_all_partial_keys<F: PrimeField>(
        partial_key_list: Vec<PartialKey>,
        limb_width: usize,
        limb_count: usize,
    ) -> Vec<F> {
        let mut combined_partial = Vec::new();

        for partial_key in partial_key_list {
            let combined_partial_limbs =
                Self::decompose_partial_key::<F>(&partial_key, limb_width, limb_count)
                    .combine_limbs();

            combined_partial.extend(combined_partial_limbs)
        }

        combined_partial
    }
}

/// AggregateWithHash extraction key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedPartialKey<F: PrimeField> {
    pub u: UnassignedInteger<F>,
    pub v: UnassignedInteger<F>,
    pub y: UnassignedInteger<F>,
    pub w: UnassignedInteger<F>,
}

impl<F: PrimeField> UnassignedPartialKey<F> {
    pub fn new(
        u: UnassignedInteger<F>,
        v: UnassignedInteger<F>,
        y: UnassignedInteger<F>,
        w: UnassignedInteger<F>,
    ) -> Self {
        Self { u, v, y, w }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        Self {
            u: UnassignedInteger::new(Value::unknown(), num_limbs),
            v: UnassignedInteger::new(Value::unknown(), num_limbs),
            y: UnassignedInteger::new(Value::unknown(), num_limbs),
            w: UnassignedInteger::new(Value::unknown(), num_limbs),
        }
    }
}

/// An assigned AggregateWithHash extraction key.
#[derive(Clone, Debug)]
pub struct AssignedPartialKey<F: PrimeField> {
    pub u: AssignedInteger<F, Fresh>,
    pub v: AssignedInteger<F, Fresh>,
    pub y: AssignedInteger<F, Fresh>,
    pub w: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedPartialKey<F> {
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
pub struct DecomposedPartialKey<F: PrimeField> {
    pub u_limbs: Vec<F>,
    pub v_limbs: Vec<F>,
    pub y_limbs: Vec<F>,
    pub w_limbs: Vec<F>,
}

impl<F: PrimeField> DecomposedPartialKey<F> {
    pub fn combine_limbs(self) -> Vec<F> {
        let mut combined = Vec::new();

        combined.extend(self.u_limbs);
        combined.extend(self.v_limbs);
        combined.extend(self.y_limbs);
        combined.extend(self.w_limbs);

        combined
    }

    pub fn to_unassigned_integers(
        self,
    ) -> (
        UnassignedInteger<F>,
        UnassignedInteger<F>,
        UnassignedInteger<F>,
        UnassignedInteger<F>,
    ) {
        let u_unassigned = UnassignedInteger::from(self.u_limbs);
        let v_unassigned = UnassignedInteger::from(self.v_limbs);
        let y_unassigned = UnassignedInteger::from(self.y_limbs);
        let w_unassigned = UnassignedInteger::from(self.w_limbs);

        (u_unassigned, v_unassigned, y_unassigned, w_unassigned)
    }
}
