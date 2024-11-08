use halo2wrong::curves::bn256::Fr;
use halo2wrong::halo2::halo2curves::bn256::{Bn256, G1Affine};

use halo2wrong::halo2::{
    plonk::*,
    poly::{commitment::Params, VerificationStrategy},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
    SerdeFormat,
};

use num_bigint::{BigUint, RandomBits};
use num_traits::One;
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use skde::key_aggregation::{AggregateRawCircuit, AggregatedKey, DecomposedAggregatedKey};
use skde::key_generation::PartialKey;
use skde::MAX_SEQUENCER_NUMBER;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    marker::PhantomData,
    path::Path,
};
// bench-mark tool
use criterion::Criterion;
pub const DEGREE: u32 = 20;

// Create the file and directory if it does not exist
fn ensure_directory_exists(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_file(path);
        fs::create_dir_all(parent).expect("Failed to create directories");
    }
}

fn write_to_file<P: AsRef<Path>>(path: P, data: &[u8]) {
    ensure_directory_exists(path.as_ref());
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("Failed to open or create file");
    file.write_all(data).expect("Failed to write to file");
    file.flush().expect("Failed to flush file");
}

fn bench_aggregate<const K: u32>(name: &str, c: &mut Criterion) {
    // define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;
    // set params for protocol
    let params_path = format!("./benches/data/params_aggregate{}", K);

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let mut buf = Vec::new();
    params.write(&mut buf).expect("Failed to write params");
    write_to_file(&params_path, &buf);

    let params_fs = File::open(params_path).expect("Failed to load params");
    let params =
        ParamsKZG::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let mut rng = thread_rng();

    let bits_len = AggregateRawCircuit::<Fr>::BIT_LEN as u64;
    let limb_width = AggregateRawCircuit::<Fr>::LIMB_WIDTH;
    let limb_count = AggregateRawCircuit::<Fr>::LIMB_COUNT;

    let max_sequencer_count = MAX_SEQUENCER_NUMBER;

    let mut n = BigUint::default();
    while n.bits() != bits_len {
        n = rng.sample(RandomBits::new(bits_len));
    }
    let n_square = &n * &n;

    let mut partial_key_list = vec![];

    let mut aggregated_key = AggregatedKey {
        u: BigUint::one(),
        v: BigUint::one(),
        y: BigUint::one(),
        w: BigUint::one(),
    };

    for _ in 0..MAX_SEQUENCER_NUMBER {
        let u = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let v = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;
        let y = rng.sample::<BigUint, _>(RandomBits::new(bits_len)) % &n;
        let w = rng.sample::<BigUint, _>(RandomBits::new(bits_len * 2)) % &n_square;

        partial_key_list.push(PartialKey {
            u: u.clone(),
            v: v.clone(),
            y: y.clone(),
            w: w.clone(),
        });

        aggregated_key.u = aggregated_key.u * &u % &n;
        aggregated_key.v = aggregated_key.v * &v % &n_square;
        aggregated_key.y = aggregated_key.y * &y % &n;
        aggregated_key.w = aggregated_key.w * &w % &n_square;
    }

    // set public input
    let combined_partial_limbs: Vec<Fr> = PartialKey::decompose_and_combine_all_partial_keys(
        partial_key_list.clone(),
        limb_width,
        limb_count,
    );

    let decomposed_aggregated_key: DecomposedAggregatedKey<Fr> =
        AggregatedKey::decompose_partial_key(&aggregated_key.clone(), limb_width, limb_count);
    let mut combined_limbs = decomposed_aggregated_key.combine_limbs();

    combined_limbs.extend(combined_partial_limbs);

    let public_inputs = [combined_limbs.as_slice()];

    let circuit = AggregateRawCircuit::<Fr> {
        n,
        n_square,
        partial_key_list,
        aggregated_key,
        max_sequencer_count,
        _f: PhantomData,
    };

    // write verifying key
    let vk_path = format!("./benches/data/vk_aggregate{}", K);

    let vk = keygen_vk(&params, &circuit.clone()).expect("keygen_vk failed");
    let mut buf = Vec::new();
    match vk.write(&mut buf, SerdeFormat::RawBytes) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error writing to buffer: {:?}", e);
        }
    }
    write_to_file(&vk_path, &buf);

    let vk_fs = File::open(vk_path).expect("Failed to load vk");
    let vk = VerifyingKey::<G1Affine>::read::<BufReader<File>, AggregateRawCircuit<Fr>>(
        &mut BufReader::new(vk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read vk");

    // write proving key
    let pk_path = format!("./benches/data/pk_aggregate{}", K);

    let pk = keygen_pk(&params, vk, &circuit.clone()).expect("keygen_pk failed");
    let mut buf = Vec::new();
    match pk.write(&mut buf, SerdeFormat::RawBytes) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Error writing to buffer: {:?}", e);
        }
    }
    write_to_file(&pk_path, &buf);

    let pk_fs = File::open(pk_path).expect("Failed to load pk");
    let pk = ProvingKey::<G1Affine>::read::<BufReader<File>, AggregateRawCircuit<Fr>>(
        &mut BufReader::new(pk_fs),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read pk");

    // benchmark the proof generation and store the proof
    let proof_path = format!("./benches/data/proof_aggregate{}", K);

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit.clone()],
                &[public_inputs.as_slice()],
                &mut OsRng,
                &mut transcript,
            )
            .expect("proof generation failed")
        })
    });
    let proof: Vec<u8> = transcript.finalize();

    write_to_file(&proof_path, &proof);

    let mut proof_fs = File::open(proof_path).expect("Failed to load proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Fail to read proof");

    // benchmark the verification
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let accept = {
                let mut transcript: Blake2bRead<&[u8], _, Challenge255<_>> =
                    TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
                VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                    verify_proof::<_, VerifierGWC<_>, _, _, _>(
                        params.verifier_params(),
                        pk.get_vk(),
                        AccumulatorStrategy::new(params.verifier_params()),
                        &[public_inputs.as_slice()],
                        &mut transcript,
                    )
                    .unwrap(),
                )
            };
            assert!(accept);
        });
    });
}

fn main() {
    let mut criterion = Criterion::default()
        .sample_size(10) // # of sample, >= 10
        .nresamples(10); // # of iteration

    let benches: Vec<Box<dyn Fn(&mut Criterion)>> =
        vec![Box::new(|c| bench_aggregate::<DEGREE>("skde aggregate", c))];

    for bench in benches {
        bench(&mut criterion);
    }
}
