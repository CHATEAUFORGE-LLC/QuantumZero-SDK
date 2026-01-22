use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quantumzero_rust_sdk::CryptoCore;

fn benchmark_key_generation(c: &mut Criterion) {
    let crypto = CryptoCore::new();
    
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            black_box(crypto.generate_key_pair())
        })
    });
}

fn benchmark_signing(c: &mut Criterion) {
    let crypto = CryptoCore::new();
    let key_pair = crypto.generate_key_pair();
    let data = b"test data for signing benchmark";
    
    c.bench_function("signing", |b| {
        b.iter(|| {
            black_box(crypto.sign_data(data, &key_pair))
        })
    });
}

fn benchmark_verification(c: &mut Criterion) {
    let crypto = CryptoCore::new();
    let key_pair = crypto.generate_key_pair();
    let data = b"test data for verification benchmark";
    let signature = crypto.sign_data(data, &key_pair);
    
    c.bench_function("verification", |b| {
        b.iter(|| {
            black_box(crypto.verify_signature(
                data,
                &signature,
                &key_pair.verifying_key,
            ))
        })
    });
}

fn benchmark_hashing(c: &mut Criterion) {
    let crypto = CryptoCore::new();
    let data = b"test data for hashing benchmark";
    
    c.bench_function("hashing", |b| {
        b.iter(|| {
            black_box(crypto.hash_data(data))
        })
    });
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_hashing
);
criterion_main!(benches);
