## Getting Started

### Requirements

This project requires a specific Rust toolchain version to ensure compatibility and optimal performance. Please ensure that your environment is set up with the following toolchain configuration:

- **Toolchain Channel**: Use the `nightly` channel of the Rust toolchain.
- **Date**: The toolchain should be specifically from `nightly-2023-10-23`.

You can set up the required toolchain using the following command with `rustup`:

```bash
rustup override set nightly-2023-10-23
```



## Running Benchmarks

This project includes benchmark tests for 'Aggregation Circuit'.


### How to Run Benchmarks

To run a specific benchmark test, use the `cargo bench` command followed by the `--bench` option with the name of the benchmark file you want to test. This command allows you to run targeted benchmark tests.

#### Running the `aggregate_with_hash` Benchmark:

```bash
cargo bench --bench aggregate_with_hash
```

## Running and Testing `delay_encryption` Feature

The `delay_encryption` feature is a key component of this project that focuses on implementing delayed encryption mechanisms. You can run and test this feature using Cargo, Rust's package manager and build tool.

### Running the Code

To run the `delay_encryption` related code, use the following command:

```bash
cargo run
```

### Testing the Feature
Use the following command to run this test:
```bash
cargo test test_single_key_delay_encryption
```