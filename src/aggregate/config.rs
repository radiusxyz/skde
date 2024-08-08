use maingate::{
    halo2::plonk::{Column, Instance},
    MainGateConfig,
};

use super::BigIntConfig;

#[derive(Clone, Debug)]
pub struct AggregateRawConfig {
    pub bigint_config: BigIntConfig,
    pub bigint_square_config: BigIntConfig,

    pub instance: Column<Instance>,

    pub limb_count: usize,
    pub limb_width: usize,
}

#[derive(Clone, Debug)]
pub struct AggregateHashConfig {
    pub bigint_config: BigIntConfig,
    pub bigint_square_config: BigIntConfig,

    pub hash_config: MainGateConfig,
    pub instance: Column<Instance>,

    pub limb_count: usize,
    pub limb_width: usize,
}
