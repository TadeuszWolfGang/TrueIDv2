//! Benchmark: identity event ingestion throughput.
//!
//! Measures upsert_mapping performance under different scenarios:
//! - New IP insertion (cold path, includes DB init)
//! - Existing IP update with same source (warm path, seed excluded)
//! - Priority resolution with source upgrade/downgrade (seed excluded)
//!
//! Run: `cargo bench -p trueid-common`

use chrono::Utc;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use trueid_common::db::{init_db, Db};
use trueid_common::model::{IdentityEvent, SourceType};

fn make_event(ip: &str, user: &str, source: SourceType, mac: Option<&str>) -> IdentityEvent {
    IdentityEvent {
        source,
        ip: ip.parse::<IpAddr>().expect("ip parse failed"),
        user: user.to_string(),
        timestamp: Utc::now(),
        raw_data: format!("bench event for {ip}"),
        mac: mac.map(|m| m.to_string()),
        confidence_score: 90,
    }
}

/// Seeds N mappings into a fresh in-memory DB. Runs on a dedicated runtime.
fn seed_db_blocking(n: usize, source: SourceType) -> Db {
    // Use a separate single-threaded runtime to avoid nesting.
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let db = init_db("sqlite::memory:").await.unwrap();
                    for i in 0..n {
                        let event = make_event(
                            &format!("10.0.{}.{}", i / 256, i % 256),
                            &format!("user-{i}"),
                            source,
                            Some(&format!(
                                "AA:BB:CC:DD:{:02X}:{:02X}",
                                i / 256,
                                i % 256
                            )),
                        );
                        db.upsert_mapping(event, Some("BenchVendor"))
                            .await
                            .unwrap();
                    }
                    db
                })
        })
        .join()
        .unwrap()
    })
}

fn new_bench_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn bench_upsert_new_ip(c: &mut Criterion) {
    c.bench_function("upsert_mapping/new_ip_x100", |b| {
        b.to_async(new_bench_rt()).iter(|| async {
            let db = init_db("sqlite::memory:").await.unwrap();
            for i in 0..100 {
                let event = make_event(
                    &format!("10.0.{}.{}", i / 256, i % 256),
                    &format!("user-{i}"),
                    SourceType::Radius,
                    Some(&format!("AA:BB:CC:DD:{:02X}:{:02X}", i / 256, i % 256)),
                );
                db.upsert_mapping(event, Some("BenchVendor")).await.unwrap();
            }
        });
    });
}

fn bench_upsert_existing_ip(c: &mut Criterion) {
    c.bench_function("upsert_mapping/warm_update_x100", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                // Setup: seed on a separate thread (not measured)
                let db = seed_db_blocking(100, SourceType::Radius);
                // Measured: update all 100
                let elapsed = std::thread::scope(|s| {
                    s.spawn(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(async {
                                let start = std::time::Instant::now();
                                for i in 0..100 {
                                    let event = make_event(
                                        &format!("10.0.{}.{}", i / 256, i % 256),
                                        &format!("user-{i}-updated"),
                                        SourceType::Radius,
                                        Some(&format!(
                                            "AA:BB:CC:DD:{:02X}:{:02X}",
                                            i / 256,
                                            i % 256
                                        )),
                                    );
                                    db.upsert_mapping(event, Some("BenchVendor"))
                                        .await
                                        .unwrap();
                                }
                                start.elapsed()
                            })
                    })
                    .join()
                    .unwrap()
                });
                total += elapsed;
            }
            total
        });
    });
}

fn bench_upsert_priority_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("upsert_mapping/priority");
    for (label, incoming, seed_with) in [
        (
            "upgrade_dhcp_to_radius",
            SourceType::Radius,
            SourceType::DhcpLease,
        ),
        (
            "downgrade_radius_to_dhcp",
            SourceType::DhcpLease,
            SourceType::Radius,
        ),
    ] {
        group.bench_with_input(
            BenchmarkId::new("resolve_x100", label),
            &(incoming, seed_with),
            |b, &(src, seed_src)| {
                b.iter_custom(|iters| {
                    let mut total = std::time::Duration::ZERO;
                    for _ in 0..iters {
                        let db = seed_db_blocking(100, seed_src);
                        let elapsed = std::thread::scope(|s| {
                            s.spawn(|| {
                                tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .unwrap()
                                    .block_on(async {
                                        let start = std::time::Instant::now();
                                        for i in 0..100 {
                                            let event = make_event(
                                                &format!(
                                                    "10.0.{}.{}",
                                                    i / 256,
                                                    i % 256
                                                ),
                                                &format!("user-{i}-new"),
                                                src,
                                                None,
                                            );
                                            db.upsert_mapping(event, None)
                                                .await
                                                .unwrap();
                                        }
                                        start.elapsed()
                                    })
                            })
                            .join()
                            .unwrap()
                        });
                        total += elapsed;
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_upsert_new_ip,
    bench_upsert_existing_ip,
    bench_upsert_priority_resolution,
);
criterion_main!(benches);
