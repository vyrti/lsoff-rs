use lsoff_rs::sys::list_listeners;
use std::time::Instant;

fn main() {
    // Warmup
    for _ in 0..5 {
        let _ = list_listeners();
    }

    let iterations = 100;
    let mut times = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t0 = Instant::now();
        let entries = list_listeners().unwrap();
        let el = t0.elapsed();
        times.push(el.as_micros() as f64);
        assert!(!entries.is_empty());
    }

    let mean_us = times.iter().sum::<f64>() / (times.len() as f64);
    let min_us = times.iter().copied().fold(f64::INFINITY, f64::min);
    let max_us = times.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    println!("==================================================================");
    println!(" Rust `list_listeners()` In-Process Execution Latency (100 runs):");
    println!("==================================================================");
    println!(
        "  Mean Latency: {:>8.2} µs ({:.3} ms)",
        mean_us,
        mean_us / 1000.0
    );
    println!(
        "  Min Latency:  {:>8.2} µs ({:.3} ms)",
        min_us,
        min_us / 1000.0
    );
    println!(
        "  Max Latency:  {:>8.2} µs ({:.3} ms)",
        max_us,
        max_us / 1000.0
    );
    println!("==================================================================");
}
