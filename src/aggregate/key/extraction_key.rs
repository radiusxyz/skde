use ff::{Field, PrimeField};

use crate::UnassignedInteger;
use crate::{AssignedInteger, Fresh};

use maingate::halo2::circuit::Value;

/// Aggregate extraction key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct UnassignedExtractionKey<F: Field> {
    pub u: UnassignedInteger<F>,
    pub v: UnassignedInteger<F>,
    pub y: UnassignedInteger<F>,
    pub w: UnassignedInteger<F>,
}

impl<F: PrimeField> UnassignedExtractionKey<F> {
    pub fn without_witness(num_limbs: usize) -> Self {
        Self {
            u: UnassignedInteger::new(Value::unknown(), num_limbs),
            v: UnassignedInteger::new(Value::unknown(), num_limbs),
            y: UnassignedInteger::new(Value::unknown(), num_limbs),
            w: UnassignedInteger::new(Value::unknown(), num_limbs),
        }
    }
}

/// An assigned Aggregate extraction key.
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
