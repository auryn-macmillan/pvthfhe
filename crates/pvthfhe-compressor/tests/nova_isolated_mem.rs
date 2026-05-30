//! Peak RSS gate for isolated Nova proving.

use std::{
    fs,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use ark_bn254::Fr;
use pvthfhe_compressor::nova::{
    encode_quad, encode_triple, DkgAggregationStepCircuit, NovaCompressor,
};
use sha2::{Digest, Sha256};

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|statm| statm.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map(|pages| pages * 4096 / 1024)
        .unwrap_or(0)
}

#[test]
fn nova_prove_peak_rss_under_12gb() {
    let stop = Arc::new(AtomicBool::new(false));
    let peak_rss_kb = Arc::new(AtomicU64::new(rss_kb()));

    let sampler_stop = Arc::clone(&stop);
    let sampler_peak = Arc::clone(&peak_rss_kb);
    let sampler = thread::spawn(move || {
        while !sampler_stop.load(Ordering::Relaxed) {
            let sample = rss_kb();
            let mut current = sampler_peak.load(Ordering::Relaxed);
            while sample > current {
                match sampler_peak.compare_exchange(
                    current,
                    sample,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        let sample = rss_kb();
        let mut current = sampler_peak.load(Ordering::Relaxed);
        while sample > current {
            match sampler_peak.compare_exchange(
                current,
                sample,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    });

    const SEED: u64 = 0x736f6e6f62655f6d;
    let seed_bytes = SEED.to_be_bytes();
    let epoch_hash: [u8; 32] = Sha256::digest(&seed_bytes).into();
    let compressor = NovaCompressor::<DkgAggregationStepCircuit<Fr>>::new(epoch_hash, 4)
        .expect("construct nova compressor");
    let acc = encode_triple((Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)));
    let public_inputs = encode_quad((
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ))
    .to_vec();
    let proof = compressor
        .prove(&acc, &public_inputs)
        .expect("prove isolated nova");
    let vk = compressor.verifier_key();

    assert!(compressor
        .verify(&vk, &proof, &acc, &public_inputs)
        .expect("verify isolated nova"));

    stop.store(true, Ordering::Relaxed);
    sampler.join().expect("join RSS sampler");

    let peak_rss_kb = peak_rss_kb.load(Ordering::Relaxed);
    assert!(
        peak_rss_kb < 12 * 1024 * 1024,
        "peak RSS under 12 GiB, observed {peak_rss_kb} KiB"
    );
}
