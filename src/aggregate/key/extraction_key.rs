use big_integer::{AssignedInteger, Fresh, UnassignedInteger};
use ff::PrimeField;

use maingate::{decompose_big, halo2::circuit::Value};
use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub struct ExtractionKey {
    pub u: BigUint,
    pub v: BigUint,
    pub y: BigUint,
    pub w: BigUint,
}
impl ExtractionKey {
    pub fn decompose_extraction_key<F: PrimeField>(
        extraction_keys: &ExtractionKey,
        limb_width: usize,
        limb_count: usize,
    ) -> DecomposedExtractionKey<F> {
        let decomposed_u = decompose_big::<F>(extraction_keys.u.clone(), limb_count, limb_width);
        let decomposed_v =
            decompose_big::<F>(extraction_keys.v.clone(), limb_count * 2, limb_width);
        let decomposed_y = decompose_big::<F>(extraction_keys.y.clone(), limb_count, limb_width);
        let decomposed_w =
            decompose_big::<F>(extraction_keys.w.clone(), limb_count * 2, limb_width);

        DecomposedExtractionKey {
            u_limbs: decomposed_u,
            v_limbs: decomposed_v,
            y_limbs: decomposed_y,
            w_limbs: decomposed_w,
        }
    }

    pub fn decompose_and_combine_all_partial_keys<F: PrimeField>(
        extraction_keys: Vec<ExtractionKey>,
        limb_width: usize,
        limb_count: usize,
    ) -> Vec<F> {
        let mut combined_partial = Vec::new();

        for key in extraction_keys {
            let decomposed_key = Self::decompose_extraction_key::<F>(&key, limb_width, limb_count);
            let combined_partial_limbs = decomposed_key.combine_limbs();
            combined_partial.extend(combined_partial_limbs)
        }

        combined_partial
    }
}

/// AggregateWithHash extraction key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedExtractionKey<F: PrimeField> {
    pub u: UnassignedInteger<F>,
    pub v: UnassignedInteger<F>,
    pub y: UnassignedInteger<F>,
    pub w: UnassignedInteger<F>,
}

impl<F: PrimeField> UnassignedExtractionKey<F> {
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
pub struct AssignedExtractionKey<F: PrimeField> {
    pub u: AssignedInteger<F, Fresh>,
    pub v: AssignedInteger<F, Fresh>,
    pub y: AssignedInteger<F, Fresh>,
    pub w: AssignedInteger<F, Fresh>,
}

impl<F: PrimeField> AssignedExtractionKey<F> {
    pub fn new(
        u: AssignedInteger<F, Fresh>,
        v: AssignedInteger<F, Fresh>,
        y: AssignedInteger<F, Fresh>,
        w: AssignedInteger<F, Fresh>,
    ) -> Self {
        Self { u, v, y, w }
    }
}

/// ???
#[derive(Clone, Debug)]
pub struct DecomposedExtractionKey<F: PrimeField> {
    pub u_limbs: Vec<F>,
    pub v_limbs: Vec<F>,
    pub y_limbs: Vec<F>,
    pub w_limbs: Vec<F>,
}

impl<F: PrimeField> DecomposedExtractionKey<F> {
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
