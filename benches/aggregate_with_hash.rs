use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    marker::PhantomData,
    path::Path,
};

// bench-mark tool
use criterion::Criterion;
use halo2wrong::{
    curves::bn256::Fr,
    halo2::{
        halo2curves::bn256::{Bn256, G1Affine},
        plonk::*,
        poly::{
            commitment::{Params, ParamsProver},
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::{ProverGWC, VerifierGWC},
                strategy::AccumulatorStrategy,
            },
            VerificationStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
        SerdeFormat,
    },
};
use maingate::{big_to_fe, decompose_big};
use num_bigint::{BigUint, RandomBits};
use num_traits::{Num, One};
use poseidon::{Poseidon, Spec};
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use skde::{
    key_aggregation::{AggregateHashCircuit, AggregatedKey},
    key_generation::PartialKey,
    MAX_SEQUENCER_NUMBER,
};
pub const DEGREE: u32 = 21;

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

fn bench_aggregate_with_hash<const K: u32>(name: &str, c: &mut Criterion) {
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

    let bit_len = AggregateHashCircuit::<Fr, 5, 4>::BIT_LEN as u64;
    let limb_width = AggregateHashCircuit::<Fr, 5, 4>::LIMB_WIDTH;
    let limb_count = AggregateHashCircuit::<Fr, 5, 4>::LIMB_COUNT;

    let max_sequencer_number = MAX_SEQUENCER_NUMBER;

    let mut n = BigUint::default();
    while n.bits() != bit_len {
        n = rng.sample(RandomBits::new(bit_len));
    }
    let n_square = &n * &n;

    let spec = Spec::<Fr, 5, 4>::new(8, 57);

    let mut partial_key_list = vec![];

    let mut aggregated_key = AggregatedKey {
        u: BigUint::one().to_str_radix(10),
        v: BigUint::one().to_str_radix(10),
        y: BigUint::one().to_str_radix(10),
        w: BigUint::one().to_str_radix(10),
    };

    for _ in 0..max_sequencer_number {
        let u = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
        let v = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) % &n_square;
        let y = rng.sample::<BigUint, _>(RandomBits::new(bit_len)) % &n;
        let w = rng.sample::<BigUint, _>(RandomBits::new(bit_len * 2)) % &n_square;

        partial_key_list.push(PartialKey {
            u: u.clone(),
            v: v.clone(),
            y: y.clone(),
            w: w.clone(),
        });

        aggregated_key.u =
            (BigUint::from_str_radix(&aggregated_key.u, 10).unwrap() * &u % &n).to_str_radix(10);
        aggregated_key.v = (BigUint::from_str_radix(&aggregated_key.v, 10).unwrap() * &v
            % &n_square)
            .to_str_radix(10);
        aggregated_key.y =
            (BigUint::from_str_radix(&aggregated_key.y, 10).unwrap() * &y % &n).to_str_radix(10);
        aggregated_key.w = (BigUint::from_str_radix(&aggregated_key.w, 10).unwrap() * &w
            % &n_square)
            .to_str_radix(10);
    }

    let mut ref_hasher = Poseidon::<Fr, 5, 4>::new_hash(8, 57);
    let base1: Fr = big_to_fe(BigUint::from(
        2_u128.pow(
            (AggregateHashCircuit::<Fr, 5, 4>::LIMB_WIDTH as u128)
                .try_into()
                .unwrap(),
        ),
    ));
    let base2: Fr = base1 * &base1;

    let mut hash_list = vec![];

    for i in 0..MAX_SEQUENCER_NUMBER {
        let u = partial_key_list[i].u.clone();
        let u_limbs = decompose_big::<Fr>(u.clone(), limb_count, limb_width);

        for i in 0..(limb_count / 3) {
            let mut u_compose = u_limbs[3 * i];
            u_compose += base1 * &u_limbs[3 * i + 1];
            u_compose += base2 * &u_limbs[3 * i + 2];
            ref_hasher.update(&[u_compose]);
        }
        let mut u_compose = u_limbs[30];
        u_compose += base1 * &u_limbs[31];
        let e = u_compose;
        ref_hasher.update(&[e.clone()]);

        let v = partial_key_list[i].v.clone();
        let v_limbs = decompose_big::<Fr>(v.clone(), limb_count * 2, limb_width);
        for i in 0..(limb_count * 2 / 3) {
            let mut v_compose = v_limbs[3 * i];
            v_compose += base1 * &v_limbs[3 * i + 1];
            v_compose += base2 * &v_limbs[3 * i + 2];
            ref_hasher.update(&[v_compose]);
        }
        let mut v_compose = v_limbs[30];
        v_compose += base1 * &v_limbs[31];
        let e = v_compose;
        ref_hasher.update(&[e.clone()]);

        let y = partial_key_list[i].y.clone();
        let y_limbs = decompose_big::<Fr>(y.clone(), limb_count, limb_width);
        for i in 0..(limb_count / 3) {
            let mut y_compose = y_limbs[3 * i];
            y_compose += base1 * &y_limbs[3 * i + 1];
            y_compose += base2 * &y_limbs[3 * i + 2];
            ref_hasher.update(&[y_compose]);
        }
        let mut y_compose = y_limbs[30];
        y_compose += base1 * &y_limbs[31];
        let e = y_compose;
        ref_hasher.update(&[e.clone()]);

        let w = partial_key_list[i].w.clone();
        let w_limbs = decompose_big::<Fr>(w.clone(), limb_count * 2, limb_width);
        for i in 0..(limb_count * 2 / 3) {
            let mut w_compose = w_limbs[3 * i];
            w_compose += base1 * &w_limbs[3 * i + 1];
            w_compose += base2 * &w_limbs[3 * i + 2];
            ref_hasher.update(&[w_compose]);
        }
        let mut w_compose = w_limbs[30];
        w_compose += base1 * &w_limbs[31];
        let e = w_compose;
        ref_hasher.update(&[e.clone()]);

        let hash = ref_hasher.squeeze(1);
        hash_list.push(hash[1]);
        hash_list.push(hash[2]);
    }

    let circuit = AggregateHashCircuit::<Fr, 5, 4> {
        spec,
        n,
        n_square,
        partial_key_list,
        max_sequencer_number,
        _f: PhantomData,
    };
    let mut public_inputs = vec![hash_list];
    public_inputs[0].extend(decompose_big::<Fr>(
        BigUint::from_str_radix(&aggregated_key.u.clone(), 10).unwrap(),
        limb_count,
        limb_width,
    ));
    public_inputs[0].extend(decompose_big::<Fr>(
        BigUint::from_str_radix(&aggregated_key.v.clone(), 10).unwrap(),
        limb_count * 2,
        limb_width,
    ));
    public_inputs[0].extend(decompose_big::<Fr>(
        BigUint::from_str_radix(&aggregated_key.y.clone(), 10).unwrap(),
        limb_count,
        limb_width,
    ));
    public_inputs[0].extend(decompose_big::<Fr>(
        BigUint::from_str_radix(&aggregated_key.w.clone(), 10).unwrap(),
        limb_count * 2,
        limb_width,
    ));

    let public_input: Vec<&[Fr]> = public_inputs.iter().map(|v| v.as_slice()).collect();

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
    let vk = VerifyingKey::<G1Affine>::read::<BufReader<File>, AggregateHashCircuit<Fr, 5, 4>>(
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
    let pk = ProvingKey::<G1Affine>::read::<BufReader<File>, AggregateHashCircuit<Fr, 5, 4>>(
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
                &[&public_input.iter().map(|&v| v).collect::<Vec<_>>()[..]],
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
                        &[&public_input.iter().map(|&v| v).collect::<Vec<_>>()[..]],
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

    let benches: Vec<Box<dyn Fn(&mut Criterion)>> = vec![Box::new(|c| {
        bench_aggregate_with_hash::<DEGREE>("skde aggregate", c)
    })];

    for bench in benches {
        bench(&mut criterion);
    }
}
