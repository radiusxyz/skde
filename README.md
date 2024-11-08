# Radius SKDE (Single Key Delay Encryption)

The Radius SKDE is a cryptographic library built in Rust for advanced encryption and key aggregation processes. This design represents a step forward from Multiparty Delay Encryption (MDE)[[KAJ+23]](https://eprint.iacr.org/2023/1612). It provides features like delayed encryption mechanisms and key aggregation circuits, which can be used in secure and privacy-preserving applications.

## Delay Encryption
Delay encryption is a cryptographic tool that employs time-lock puzzles to enforce a predetermined delay on the availability of a decryption key. This method ensures that encrypted data cannot be decrypted until a specified amount of computational work, often measured in time, has been completed.

As its core, delay encryption involves two main phases: encryption and timed decryption. During the encryption phase, data is encrypted using a standard cryptographic algorithm, and a time-lock puzzle is generated. This puzzle is constructed in such a way that solving it requires a predictable amount of computational effort, effectively creating a “delay” before the information can be accessed.

## Key Aggregation Circuit
We introduce a novel idea for the aggregation process within the SKDE framework. Instead of naively storing all partial keys, only the committed values are revealed. To ensure that the aggregation has been performed correctly, we incorporate a circuit to prove this with zero-knowledge proofs (ZKP). This new aggregation process significantly reduces the gas fees associated with public key storage in MDE, enhancing overall system efficiency while maintaining the integrity of the aggregation process.

For more information, refer to the following link: [Radius SKDE on EthResearch](https://ethresear.ch/t/radius-skde-enhancing-rollup-composability-with-trustless-sequencing/19185)


# Example

The Radius SKDE provides a suite of tests and benchmarks to validate and assess the performance of its cryptographic features, especially for delay encryption and key aggregation.


## Running Tests

To test the `delay_encryption` feature, use the following command:

```bash
cargo test test_single_key_delay_encryption
```

This test performs the following steps:

1. **Setup Parameters**: Generates two large prime numbers $p$ and $q$ to create an RSA modulus $n = p * q$. Set all the parameters including a generator $g$ that will be used for base of exponentiation operation and the delay time parameter and maximun number of sequencer to set.
2. **Generate Partial Keys and Proofs**: Creates partial keys and validity proofs for each sequencer. **(TODO)** In a complete implementation, range proofs would be used to ensure that the aggregated keys represent a unique combination of partial keys.
3. **Verify All Generated Partial Keys**: Confirms the validity of all generated keys.
4. **Aggregate Partial Keys**: Combines partial keys into a single aggregated key.
5. **Encrypt a Message**: Encrypts a test message using the aggregated key.
6. **Solve Time-lock Puzzle**: Solves a time-lock puzzle to retrieve the secret key.
7. **Decrypt the Cipher Text**: Decrypts the encrypted message and checks it matches the original.


Note that, in a standard implementation, large prime numbers $p$ and $q$ would be securely generated to calculate the RSA modulus $N = p \times q$. Once $N$ is calculated, the values of $p$ and $q$ are discarded to ensure cryptographic security. However, for testing purposes, we initialize these parameters using fixed primes.

Step 2 must include a range proof to ensure that the aggregated keys uniquely represent the combination of partial keys. This can be achieved using zero-knowledge proof circuit. (This will be implemented soon.)

This test ensures the delay encryption feature is functioning correctly and verifies key generation, encryption, decryption, and time-lock puzzle-solving processes.

## Running Benchmarks

Benchmark tests in this SDK are designed to evaluate performance of zkCircuit proving for aggregation.

To run a specific benchmark test, use the `cargo bench` command followed by the `--bench` option with the benchmark file name. This command allows you to run targeted benchmark tests.

### Running the `aggregate_with_hash` Benchmark

```bash
cargo bench --bench aggregate_with_hash
```

This command benchmarks the performance of the `aggregate_with_hash` function, which combines partial keys from multiple sequencers.


## Additional Configuration

This SKDE includes parameters for cryptographic configurations, such as bit length, prime values, and a generator. You can find these constants in the `lib.rs` file:

- **MAX_SEQUENCER_NUMBER**: $2$ (default for this project)
- **BIT_LEN**: $2048$ (bit length of $n$)
- **PRIME_P, PRIME_Q**: Large prime numbers for key generation
- **GENERATOR**: A constant value used in cryptographic functions
- **TIME_PARAM_T**: $2$ (defines delay time as $2$`^TIME_PARAM_T`)

These constants define the environment and security parameters for delay encryption and key aggregation circuit.

## Contributing
We appreciate your contributions to our project. Visit [issues](https://github.com/radiusxyz/skde/issues) page to start with or refer to the [Contributing guide](https://github.com/radiusxyz/radius-docs-bbs/blob/main/docs/contributing_guide.md).

## Getting Help
If you cannot find answers from our Guides(WIP) and Documentation(WIP), refer to [Getting Help](https://github.com/radiusxyz/radius-docs-bbs/blob/main/getting_help.md).
