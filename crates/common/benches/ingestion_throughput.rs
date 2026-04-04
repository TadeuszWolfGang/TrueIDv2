//! Benchmark: identity event ingestion throughput.
//!
//! Measures upsert_mapping performance under different scenarios:
//! - New IP insertion (cold path)
//! - Existing IP update with same source (warm path)
//! - Priority resolution with source upgrade/downgrade
//!
//! Run: `cargo bench -p trueid-common`

use chrono::Utc;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use trueid_common::db::init_db;
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

fn bench_upsert_new_ip(c: &mut Criterion) {
    c.bench_function("upsert_mapping/new_ip_x100", |b| {
        b.to_async(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        )
        .iter(|| async {
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
    c.bench_function("upsert_mapping/existing_ip_update_x100", |b| {
        b.to_async(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
        )
        .iter(|| async {
            let db = init_db("sqlite::memory:").await.unwrap();
            // Seed 100 mappings
            for i in 0..100 {
                let event = make_event(
                    &format!("10.0.{}.{}", i / 256, i % 256),
                    &format!("user-{i}"),
                    SourceType::Radius,
                    Some(&format!("AA:BB:CC:DD:{:02X}:{:02X}", i / 256, i % 256)),
                );
                db.upsert_mapping(event, Some("BenchVendor")).await.unwrap();
            }
            // Update all 100 (warm path)
            for i in 0..100 {
                let event = make_event(
                    &format!("10.0.{}.{}", i / 256, i % 256),
                    &format!("user-{i}-updated"),
                    SourceType::Radius,
                    Some(&format!("AA:BB:CC:DD:{:02X}:{:02X}", i / 256, i % 256)),
                );
                db.upsert_mapping(event, Some("BenchVendor")).await.unwrap();
            }
        });
    });
}

fn bench_upsert_priority_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("upsert_mapping/priority");
    for (label, source) in [
        ("upgrade_dhcp_to_radius", SourceType::Radius),
        ("downgrade_radius_to_dhcp", SourceType::DhcpLease),
    ] {
        group.bench_with_input(BenchmarkId::new("resolve_x100", label), &source, |b, &src| {
            b.to_async(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            )
            .iter(|| {
                let src = src;
                async move {
                    let db = init_db("sqlite::memory:").await.unwrap();
                    let seed_source = if src == SourceType::Radius {
                        SourceType::DhcpLease
                    } else {
                        SourceType::Radius
                    };
                    for i in 0..100 {
                        let event = make_event(
                            &format!("10.0.{}.{}", i / 256, i % 256),
                            &format!("user-{i}"),
                            seed_source,
                            None,
                        );
                        db.upsert_mapping(event, None).await.unwrap();
                    }
                    for i in 0..100 {
                        let event = make_event(
                            &format!("10.0.{}.{}", i / 256, i % 256),
                            &format!("user-{i}-new"),
                            src,
                            None,
                        );
                        db.upsert_mapping(event, None).await.unwrap();
                    }
                }
            });
        });
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
