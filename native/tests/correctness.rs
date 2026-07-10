//! MIH must be *exact*: for every query, its result equals the brute-force set
//! of ids within radius `r`. These tests check that equality across random
//! data, several `m`, and several radii — including the twinflame R=12 regime.

use tfls_mih::{Entry, MihStore};

/// xorshift128+ style small deterministic RNG (no external crates).
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

fn brute(codes: &[u128], ids: &[u64], q: u128, r: u32) -> Vec<u64> {
    let mut v: Vec<u64> = codes
        .iter()
        .zip(ids)
        .filter(|(c, _)| (**c ^ q).count_ones() <= r)
        .map(|(_, id)| *id)
        .collect();
    v.sort_unstable();
    v
}

fn flip(mut code: u128, bits: u32, rng: &mut Rng) -> u128 {
    for _ in 0..bits {
        code ^= 1u128 << (rng.below(128) as u32);
    }
    code
}

#[test]
fn exact_matches_brute_force_across_params() {
    let mut rng = Rng::new(42);
    let n = 4000;
    let codes: Vec<u128> = (0..n).map(|_| rng.u128()).collect();
    let ids: Vec<u64> = (0..n as u64).collect();
    let entries: Vec<Entry> = codes
        .iter()
        .zip(&ids)
        .map(|(&code, &id)| Entry { code, id })
        .collect();

    for &m in &[6usize, 8, 13] {
        let store = MihStore::build(&entries, m);
        for &r in &[0u32, 3, 8, 12, 20] {
            for _ in 0..40 {
                // mix exact-planted queries with random ones
                let q = if rng.below(2) == 0 {
                    flip(codes[rng.below(n)], rng.below((r + 2) as usize) as u32, &mut rng)
                } else {
                    rng.u128()
                };
                let mut got = store.query(q, r);
                got.sort_unstable();
                let want = brute(&codes, &ids, q, r);
                assert_eq!(
                    got, want,
                    "mismatch m={m} r={r}: got {} want {}",
                    got.len(),
                    want.len()
                );
            }
        }
    }
}

#[test]
fn self_lookup_is_distance_zero() {
    let mut rng = Rng::new(7);
    let entries: Vec<Entry> = (0..2000)
        .map(|i| Entry { code: rng.u128(), id: i })
        .collect();
    let store = MihStore::build(&entries, 8);
    for e in &entries {
        let hits = store.query_with_dist(e.code, 0);
        assert!(hits.iter().any(|&(id, d)| id == e.id && d == 0));
    }
}

#[test]
fn empty_store_is_safe() {
    let store = MihStore::build(&[], 6);
    assert!(store.is_empty());
    assert!(store.query(123, 12).is_empty());
}
