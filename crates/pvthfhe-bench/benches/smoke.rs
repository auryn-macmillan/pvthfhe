use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_noop(c: &mut Criterion) {
    c.bench_function("noop", |b| b.iter(|| black_box(42u64)));
}

criterion_group!(benches, bench_noop);
criterion_main!(benches);
