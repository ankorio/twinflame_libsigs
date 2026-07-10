//! Benchmark: build time, query latency, and candidate counts for the native
//! MIH store at twinflame's R=12, across substring counts `m` and dataset sizes.
//! Compare the query numbers against the Python prototype (~50–100 µs/class).

use std::time::Instant;
use tfls_mih::{suggest_m, Entry, MihStore};

struct Rng(u64, u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E3779B97F4A7C15, seed.wrapping_mul(0xD1B54A32D192ED03) | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut s1 = self.0;
        let s0 = self.1;
        self.0 = s0;
        s1 ^= s1 << 23;
        self.1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
        self.1.wrapping_add(s0)
    }
    fn u128(&mut self) -> u128 {
        ((self.next_u64() as u128) << 64) | self.next_u64() as u128
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

fn main() {
    let r: u32 = 12;
    for &n in &[200_000usize, 1_000_000, 5_000_000] {
        let mut rng = Rng::new(1);
        let entries: Vec<Entry> = (0..n)
            .map(|i| Entry { code: rng.u128(), id: i as u64 })
            .collect();

        let ms = vec![6usize, 8, 13, 16];
        println!("\nN = {n} (suggest_m = {}), radius = {r}", suggest_m(n));
        println!(
            "{:>4} {:>10} {:>12} {:>14} {:>16}",
            "m", "build(s)", "query(us)", "cand/query", "per-10k-app(s)"
        );

        // realistic query mix: 30% near-neighbour (in-set), 70% miss
        let n_queries = 20_000;
        let queries: Vec<u128> = (0..n_queries)
            .map(|_| {
                if rng.below(10) < 3 {
                    let mut c = entries[rng.below(n)].code;
                    for _ in 0..rng.below((r + 1) as usize) {
                        c ^= 1u128 << (rng.below(128) as u32);
                    }
                    c
                } else {
                    rng.u128()
                }
            })
            .collect();

        for &m in &ms {
            let t0 = Instant::now();
            let store = MihStore::build(&entries, m);
            let build_s = t0.elapsed().as_secs_f64();

            let t0 = Instant::now();
            let mut total_hits = 0usize;
            for &q in &queries {
                total_hits += store.query(q, r).len();
            }
            let per_query_us = t0.elapsed().as_secs_f64() * 1e6 / n_queries as f64;
            let per_app = per_query_us * 10_000.0 / 1e6;
            println!(
                "{:>4} {:>10.2} {:>12.2} {:>14.2} {:>16.3}   (hits={total_hits})",
                m,
                build_s,
                per_query_us,
                total_hits as f64 / n_queries as f64,
                per_app
            );
        }
    }
}
