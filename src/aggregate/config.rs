use maingate::halo2::plonk::{Column, Instance};

use super::BigIntConfig;

#[derive(Clone, Debug)]
pub struct AggregateConfig {
    pub bigint_config: BigIntConfig,
    pub bigint_square_config: BigIntConfig,
    pub instance: Column<Instance>,
}
