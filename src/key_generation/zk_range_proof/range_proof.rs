use std::{env, time::Instant};

use anyhow::{Context, Result};
use num_bigint::BigUint;
use risc0_zkvm::{
    get_prover_server, ExecutorEnv, ExecutorImpl, ProveInfo, ProverOpts, Receipt, VerifierContext,
};

/// ELF binary for range proof execution
pub const RANGE_PROOF_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/key_generation/zk_range_proof/range_proof.bin"
));

/// Unique ID used for range proof ELF
pub const RANGE_PROOF_ID: [u32; 8] = [
    3975637365, 3132349927, 1261025718, 3120425263, 88843406, 3451875883, 263096980, 3681459231,
];

/// Default modulus value (1024bits)
pub const MODULUS: &str = "109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129";
/// Default base value for exponentiation
pub const BASE: &str = "4";
/// Ragne for range proof
pub const RANGE: &str =
    "32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596230656";
/// Exponent value
pub const EXPONENT: &str = "462000193083985684610660351369692616274581519034636217798321";

/// Input for range proof generation
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RangeProofInput {
    pub base: BigUint,
    pub modulus: BigUint,
    pub exponent: BigUint,
    pub range: BigUint,
}

impl RangeProofInput {
    /// Create a new RangeProofInput with custom inputs
    pub fn new(base: BigUint, modulus: BigUint, exponent: BigUint, range: BigUint) -> Self {
        RangeProofInput {
            base,
            modulus,
            exponent,
            range,
        }
    }
}

/// Output for range proof execution results
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct RangeProofOutput {
    pub base: BigUint,
    pub modulus: BigUint,
    pub range: BigUint,
    pub u: BigUint,
}

/// Set up RISC Zero execution environment
///
/// Serializes input data and configures execution environment
pub(crate) fn setup_env<'a>(input: &RangeProofInput) -> Result<ExecutorEnv<'a>> {
    let serialized = bincode::serialize(input).context("Failed to serialize range proof input")?;

    ExecutorEnv::builder()
        .write_slice(&serialized)
        .build()
        .context("Failed to build executor environment")
}

/// Generate a single range proof
///
/// Takes input and runs it in RISC Zero environment to generate proof
pub fn generate_range_proof(input: &RangeProofInput) -> Result<ProveInfo> {
    let env = setup_env(input)?;

    let mut exec = ExecutorImpl::from_elf(env, RANGE_PROOF_ELF)
        .context("Failed to create executor from ELF")?;

    // Start execution session and measure time
    let exec_start = Instant::now();
    let session = exec.run().context("Failed to execute RISC Zero session")?;
    let exec_duration = exec_start.elapsed();
    println!("Session execution completed in {:?}", exec_duration);

    // Get prover server with succinct proof options
    let prover =
        get_prover_server(&ProverOpts::succinct()).context("Failed to get prover server")?;

    let ctx = VerifierContext::default();

    // Generate proof and measure time
    println!("Starting proof generation...");
    let proof_start = Instant::now();
    let prove_info = prover
        .prove_session(&ctx, &session)
        .context("Failed to generate proof")?;
    let proof_duration = proof_start.elapsed();
    println!("Proof generation completed in {:?}", proof_duration);

    Ok(prove_info)
}

/// Verify a single proof
///
/// Compares expected partial key with proof and verifies
pub fn verify_range_proof(partial_key_u: BigUint, receipt: &Receipt) -> Result<()> {
    // Decode result data from proof
    let output: RangeProofOutput = receipt
        .journal
        .decode()
        .context("Failed to decode range proof output")?;
    println!("u: {}, range: {}", output.u, output.range);

    // Verify proof and measure time
    println!("Starting verification...");
    let verify_start = Instant::now();
    receipt
        .verify(RANGE_PROOF_ID)
        .context("Failed to verify receipt")?;
    let verify_duration = verify_start.elapsed();
    println!("Verification completed in {:?}", verify_duration);

    // Check if partial key matches
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

/// Verify multiple proofs sequentially
///
/// Verifies each proof one by one and checks partial key
pub fn verify_proofs(partial_keys: Vec<BigUint>, receipts: &[Receipt]) -> Result<()> {
    println!(
        "Starting sequential verification for {} receipts...",
        receipts.len()
    );
    let verify_start = Instant::now();

    // Check if the number of keys matches the number of receipts
    if partial_keys.len() != receipts.len() {
        return Err(anyhow::anyhow!(
            "Number of partial keys ({}) does not match number of receipts ({})",
            partial_keys.len(),
            receipts.len()
        ));
    }

    // Process all proofs sequentially
    for (i, (partial_key_u, receipt)) in partial_keys.iter().zip(receipts.iter()).enumerate() {
        let output: RangeProofOutput = receipt
            .journal
            .decode()
            .context("Failed to decode range proof output")?;
        println!(
            "[{}/{}] u: {}, range: {}",
            i + 1,
            receipts.len(),
            output.u,
            output.range
        );

        // Verify proof
        receipt
            .verify(RANGE_PROOF_ID)
            .context("Failed to verify receipt")?;

        // Check partial key match
        if partial_key_u != &output.u {
            return Err(anyhow::anyhow!(
                "Partial key mismatch in receipt {}: expected {}, found {}",
                i + 1,
                partial_key_u,
                output.u
            ));
        }
    }

    let verify_duration = verify_start.elapsed();
    println!("Sequential verification completed in {:?}", verify_duration);
    println!("All {} receipts verified successfully", receipts.len());
    Ok(())
}

/// Verify multiple proofs in parallel
///
/// Uses Rayon library to process all proofs in parallel for better performance
pub fn verify_proofs_parallel(partial_keys: Vec<BigUint>, receipts: &[Receipt]) -> Result<()> {
    use rayon::prelude::*;

    println!(
        "Starting parallel verification for {} receipts...",
        receipts.len()
    );
    let verify_start = Instant::now();

    // Check if the number of keys matches the number of receipts
    if partial_keys.len() != receipts.len() {
        return Err(anyhow::anyhow!(
            "Number of partial keys ({}) does not match number of receipts ({})",
            partial_keys.len(),
            receipts.len()
        ));
    }

    // Process all proofs in parallel and collect errors
    let results: Vec<Result<()>> = partial_keys
        .par_iter()
        .zip(receipts.par_iter())
        .enumerate()
        .map(|(i, (partial_key_u, receipt))| {
            let output: RangeProofOutput = receipt
                .journal
                .decode()
                .context("Failed to decode range proof output")?;

            // Output may be mixed due to parallel processing
            println!(
                "[{}/{}] u: {}, range: {}",
                i + 1,
                receipts.len(),
                output.u,
                output.range
            );

            // Verify proof
            receipt
                .verify(RANGE_PROOF_ID)
                .context("Failed to verify receipt")?;

            // Check partial key match
            if partial_key_u != &output.u {
                return Err(anyhow::anyhow!(
                    "Partial key mismatch in receipt {}: expected {}, found {}",
                    i + 1,
                    partial_key_u,
                    output.u
                ));
            }

            Ok(())
        })
        .collect();

    // Check for verification failures
    for result in results {
        if let Err(e) = result {
            return Err(e);
        }
    }

    let verify_duration = verify_start.elapsed();
    println!("Parallel verification completed in {:?}", verify_duration);
    println!("All {} receipts verified successfully", receipts.len());
    Ok(())
}
