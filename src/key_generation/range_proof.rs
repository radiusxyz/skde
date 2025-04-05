use num_bigint::BigUint;
use num_traits::identities::Zero;
use risc0_zkvm::{
    get_prover_server, ExecutorEnv, ExecutorImpl, ProveInfo, ProverOpts, Receipt, VerifierContext,
};
use std::env;
use std::str::FromStr;
use std::time::Instant;

pub const RANGE_PROOF_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/key_generation/range_proof"
));

pub const RANGE_PROOF_ID: [u32; 8] = [
    3132233165, 132287651, 2505256472, 239450056, 1119461797, 27748644, 1197710131, 95873165,
];

pub const MODULUS: &str = "109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129";
pub const BASE: &str = "4";
pub const RANGE: &str =
    "54228695914669666723440166889041962662973721213812451561550491637090461709551";
pub const EXPONENT: &str = "462000193083985684610660351369692616274581519034636217798321";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Input {
    pub base: BigUint,
    pub modulus: BigUint,
    pub range: BigUint,
    pub result: BigUint, // the result is base^exponent under modulus
}

impl Input {
    // Constructor using default constants
    pub fn new_default() -> Self {
        Self::new(BASE, MODULUS, RANGE)
    }

    // Constructor that allows custom input
    pub fn new(base_str: &str, modulus_str: &str, range_str: &str) -> Self {
        let base = BigUint::from_str(base_str).expect("Invalid number for Base");
        let modulus = BigUint::from_str(modulus_str).expect("Invalid number for Modulus");
        let range = BigUint::from_str(range_str).expect("Invalid number for Range");

        let result = if modulus.is_zero() {
            BigUint::zero()
        } else {
            Self::calculate_private_modular_exponentiation(&base, &modulus)
        };

        println!("Initial parameter settings");
        println!("Base: {}", base);
        println!("Modulus: {}", modulus);
        println!("Range: {}", range);
        println!("Result of base^exponent % modulus: {}", result);

        Input {
            base,
            modulus,
            range,
            result,
        }
    }

    pub fn calculate_private_modular_exponentiation(base: &BigUint, modulus: &BigUint) -> BigUint {
        let exponent = BigUint::from_str(EXPONENT).expect("Invalid number for Exponent");
        if modulus.is_zero() {
            BigUint::zero()
        } else {
            base.modpow(&exponent, modulus)
        }
    }
}

pub fn setup_inputs() -> (BigUint, BigUint, BigUint, BigUint) {
    let input = Input::new_default();

    (input.base, input.modulus, input.range, input.result)
}

pub fn setup_env<'a>(
    base: &'a BigUint,
    modulus: &'a BigUint,
    range: &'a BigUint,
    result: &'a BigUint,
) -> ExecutorEnv<'a> {
    let input = Input {
        base: base.clone(),
        modulus: modulus.clone(),
        range: range.clone(),
        result: result.clone(),
    };

    ExecutorEnv::builder()
        .write_slice(&bincode::serialize(&input).unwrap())
        .build()
        .unwrap()
}

pub fn generate_range_proof(env: ExecutorEnv) -> ProveInfo {
    println!("current dir: {:?}", env::current_dir().unwrap());

    let mut exec = ExecutorImpl::from_elf(env, RANGE_PROOF_ELF).unwrap();
    let exec_start = Instant::now();
    let session = exec.run().unwrap();
    let exec_duration = exec_start.elapsed();
    println!("Session execution completed in {:?}", exec_duration);

    // Recursive proving, fast verification
    let prover = get_prover_server(&ProverOpts::succinct()).unwrap();
    // Fast proving, slow verification
    // let prover = get_prover_server(&ProverOpts::fast()).unwrap();
    let ctx = VerifierContext::default();

    println!("Starting proof generation...");
    let proof_start = Instant::now();
    let prove_info = prover.prove_session(&ctx, &session).unwrap();
    let proof_duration = proof_start.elapsed();
    println!("Proof generation completed in {:?}", proof_duration);
    prove_info
}

pub fn verify_proof(receipt: &Receipt) {
    println!("Starting verification...");
    let verify_start = Instant::now();
    receipt.verify(RANGE_PROOF_ID).unwrap();
    let verify_duration = verify_start.elapsed();
    println!("Verification completed in {:?}", verify_duration);

    println!("Verified");
}
