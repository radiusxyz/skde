use anyhow::{Context, Result};
use num_bigint::BigUint;
use risc0_zkvm::{
    get_prover_server, ExecutorEnv, ExecutorImpl, ProveInfo, ProverOpts, Receipt, VerifierContext,
};
use std::env;
use std::time::Instant;

pub const RANGE_PROOF_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/range_proof/range_proof"
));

pub const RANGE_PROOF_ID: [u32; 8] = [
    2853987573, 2306891643, 1372111899, 3734673277, 3052955973, 1620853738, 1113992147, 2156397505,
];

pub const MODULUS: &str = "109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129";
pub const BASE: &str = "4";
pub const RANGE: &str =
    "54228695914669666723440166889041962662973721213812451561550491637090461709551";
pub const EXPONENT: &str = "462000193083985684610660351369692616274581519034636217798321";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RangeProofInput {
    pub base: BigUint,
    pub modulus: BigUint,
    pub range: BigUint,
}

impl RangeProofInput {
    // Constructor that allows custom input
    pub fn new(base: BigUint, modulus: BigUint, range: BigUint) -> Self {
        RangeProofInput {
            base,
            modulus,
            range,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RangeProofOutput {
    pub base: BigUint,
    pub modulus: BigUint,
    pub range: BigUint,
    pub u: BigUint,
}

pub(crate) fn setup_env<'a>(input: &RangeProofInput) -> Result<ExecutorEnv<'a>> {
    let serialized = bincode::serialize(input).context("Failed to serialize range proof input")?;

    ExecutorEnv::builder()
        .write_slice(&serialized)
        .build()
        .context("Failed to build executor environment")
}

pub fn generate_range_proof(input: &RangeProofInput) -> Result<ProveInfo> {
    let env = setup_env(input)?;

    let mut exec = ExecutorImpl::from_elf(env, RANGE_PROOF_ELF)
        .context("Failed to create executor from ELF")?;

    let exec_start = Instant::now();
    let session = exec.run().context("Failed to execute RISC Zero session")?;
    let exec_duration = exec_start.elapsed();
    println!("Session execution completed in {:?}", exec_duration);

    let prover =
        get_prover_server(&ProverOpts::succinct()).context("Failed to get prover server")?;

    let ctx = VerifierContext::default();

    println!("Starting proof generation...");
    let proof_start = Instant::now();
    let prove_info = prover
        .prove_session(&ctx, &session)
        .context("Failed to generate proof")?;
    let proof_duration = proof_start.elapsed();
    println!("Proof generation completed in {:?}", proof_duration);

    Ok(prove_info)
}

pub fn verify_proof(partial_key_u: BigUint, receipt: &Receipt) -> Result<()> {
    let output: RangeProofOutput = receipt
        .journal
        .decode()
        .context("Failed to decode range proof output")?;
    println!("u: {}, range: {}", output.u, output.range);

    println!("Starting verification...");
    let verify_start = Instant::now();
    receipt
        .verify(RANGE_PROOF_ID)
        .context("Failed to verify receipt")?;
    let verify_duration = verify_start.elapsed();
    println!("Verification completed in {:?}", verify_duration);

    if partial_key_u != output.u {
        return Err(anyhow::anyhow!(
            "Partial key mismatch: expected {}, found {}",
            partial_key_u,
            output.u
        ));
    }

    println!("Verified");
    Ok(())
}
