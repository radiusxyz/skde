use anyhow::Result;
use num_bigint::BigUint;
use num_traits::Num;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

use super::{
    zk_range_proof::{generate_range_proof, verify_range_proof, RangeProofInput},
    sigma_proof::{generate_sigma_proof, verify_sigma_proof, SigmaProof},
    PartialKey, SecretValue,
};
use crate::delay_encryption::SkdeParams;

#[derive(Debug, Clone)]
pub struct UVPair {
    pub u: BigUint,
    pub v: BigUint,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialKeyProof {
    pub sigma: SigmaProof,
    pub range_proof: Receipt,
}

pub fn prove_partial_key_validity(
    skde_params: &SkdeParams,
    secret_value: &SecretValue,
) -> Result<PartialKeyProof> {
    // Sigma proof generation
    let sigma = generate_sigma_proof(skde_params, secret_value)?;
    let n = BigUint::from_str_radix(&skde_params.n, 10)?;
    let g = BigUint::from_str_radix(&skde_params.g, 10)?;
    let max_sequencer_number = BigUint::from_str_radix(&skde_params.max_sequencer_number, 10)?;
    let exp = &secret_value.r + &secret_value.s;
    let range = &n / max_sequencer_number;

    // Range proof input
    let input = RangeProofInput {
        base: g,
        modulus: n,
        exponent: exp,
        range,
    };

    let receipt = generate_range_proof(&input)?.receipt;

    Ok(PartialKeyProof {
        sigma,
        range_proof: receipt,
    })
}

pub fn verify_partial_key_validity(
    skde_params: &SkdeParams,
    partial_key: &PartialKey,
    partial_key_proof: &PartialKeyProof,
) -> Result<bool> {
    // Verify sigma proof
    let sigma_valid = verify_sigma_proof(skde_params, partial_key, &partial_key_proof.sigma)?;
    if !sigma_valid {
        return Err(anyhow::anyhow!("Sigma proof verification failed"));
    }

    // Verify range proof receipt
    verify_range_proof(partial_key.u.clone(), &partial_key_proof.range_proof)?;

    Ok(true)
}
