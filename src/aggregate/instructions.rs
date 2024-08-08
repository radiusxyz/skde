use crate::aggregate::{
    AssignedAggregatePartialKeys, AssignedAggregatePublicParams, AssignedExtractionKey,
    UnassignedAggregatePublicParams, UnassignedExtractionKey,
};
use ff::PrimeField;
use halo2wrong::halo2::plonk::Error;
use maingate::RegionCtx;

pub trait AggregateInstructions<F: PrimeField> {
    fn assign_public_params(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        public_params: UnassignedAggregatePublicParams<F>,
    ) -> Result<AssignedAggregatePublicParams<F>, Error>;

    fn assign_extraction_key(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        extraction_key: UnassignedExtractionKey<F>,
    ) -> Result<AssignedExtractionKey<F>, Error>;

    fn aggregate(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        partial_keys: &AssignedAggregatePartialKeys<F>,
        public_params: &AssignedAggregatePublicParams<F>,
    ) -> Result<AssignedExtractionKey<F>, Error>;
}
