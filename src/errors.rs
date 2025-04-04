// use anyhow::{Context, Result};
// use risc0_zkvm::serde::Error as Risc0SerdeError;
// use thiserror::Error;

// #[derive(Error, Debug)]
// pub enum SkdeError {
//     #[error("Failed to parse BigUint from string: {0}")]
//     BigUintParseError(String),
//     #[error("Failed to verify partial key validity")]
//     PartialKeyMismatch,
//     #[error("Failed to decode receipt")]
//     ReceiptDecodeError(#[from] Risc0SerdeError),
//     #[error("Failed to verify receipt")]
//     ReceiptVerificationError,
//     #[error("Failed to setup executor env")]
//     ExecutorEnvError,
//     #[error("Failed to serialize input: {0}")]
//     SerializationError(#[from] bincode::Error),
//     #[error("Failed to create executor: {0}")]
//     ExecutorCreationError(String),
//     #[error("Failed to execute session: {0}")]
//     SessionExecutionError(String),
//     #[error("Failed to get prover server: {0}")]
//     ProverServerError(String),
//     #[error("Failed to generate proof: {0}")]
//     ProofGenerationError(String),
// }
