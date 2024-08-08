use crate::{
    key_aggregation::{AssignedKeyAggregationPublicParams, UnassignedKeyAggregationPublicParams},
    key_generation::{AssignedPartialKey, UnassignedPartialKey},
};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;

use super::AssignedExtractionKey;

pub trait AggregateInstructions<F: PrimeField> {
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: UnassignedKeyAggregationPublicParams<F>,
    ) -> Result<AssignedKeyAggregationPublicParams<F>, Error>;

    fn assign_partial_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        unassigned_partial_key: UnassignedPartialKey<F>,
    ) -> Result<AssignedPartialKey<F>, Error>;

    fn aggregate_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        assigned_extraction_key: &AssignedExtractionKey<F>,
        public_params: &AssignedKeyAggregationPublicParams<F>,
    ) -> Result<AssignedPartialKey<F>, Error>;
}
