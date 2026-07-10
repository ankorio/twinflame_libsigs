//! Multi-Index Hashing (MIH) store for 128-bit twinflame signatures.
//!
//! Implements Norouzi, Punjani & Fleet, "Fast Exact Search in Hamming Space
//! with Multi-Index Hashing" (IEEE TPAMI 2014). This is the principled,
//! storage-efficient answer to the problem the Python prototype's design study
//! ran into: exact radius-`r` Hamming search at large `r` (twinflame's R=12)
//! needs only `m` substring tables, not Manku's `C(r,q)` copies.
//!
//! ## The pigeonhole guarantee
//!
//! Split each 128-bit code into `m` disjoint substrings. If two codes are within
//! Hamming distance `r`, then in at least one substring they differ by at most
//! `floor(r/m)` bits (else the total would exceed `r`). So: build one hash table
//! per substring; to answer a radius-`r` query, search every table for
//! substrings within `floor(r/m)` of the query's substring, union the
//! candidates, and verify the full 128-bit distance. Exact, no false negatives;
//! false positives are removed by the verify step.
//!
//! Choosing `m ≈ 128 / log2(N)` makes the per-substring radius small (ideally 0
//! or 1), which is the regime where a substring table is a direct-indexed
//! bucket array — the "rainbow table" shard lookup, now exact.

#[cfg(feature = "python")]
mod python;

/// Widest substring the direct-index directory will allocate for (2^24 buckets
/// = 64 MB/table). Forces sensible MIH configs (m ≥ 6 for 128-bit codes).
pub const MAX_SUBSTRING_BITS: u32 = 24;

/// A stored fingerprint: the 128-bit signature and an opaque payload id
/// (index into the caller's coordinate/version-range sidecar).
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub code: u128,
    pub id: u64,
}

/// One substring index: a direct bucket array over `width`-bit substring values.
struct Table {
    shift: u32,
    width: u32,
    mask: u128,
    /// `dir[b]..dir[b+1]` is the slice of `positions` whose substring == b.
    dir: Vec<u32>,
    /// entry indices (into `codes`/`ids`), grouped by substring value.
    positions: Vec<u32>,
}

impl Table {
    #[inline]
    fn substring(&self, code: u128) -> u32 {
        ((code >> self.shift) & self.mask) as u32
    }
}

pub struct MihStore {
    codes: Vec<u128>,
    ids: Vec<u64>,
    tables: Vec<Table>,
    m: usize,
}

impl MihStore {
    /// Build a store over `entries`, splitting the 128-bit code into `m`
    /// near-equal substrings. `m` controls the storage/speed tradeoff; a good
    /// default is `suggest_m(entries.len())`.
    pub fn build(entries: &[Entry], m: usize) -> Self {
        assert!(m >= 1 && m <= 128, "m out of range");
        let n = entries.len();
        let codes: Vec<u128> = entries.iter().map(|e| e.code).collect();
        let ids: Vec<u64> = entries.iter().map(|e| e.id).collect();

        let bounds = substring_bounds(m);
        // Direct-index directories cost 2^width slots, so substrings must be
        // narrow — which is exactly how MIH is meant to be configured (many
        // small tables so the per-substring radius is 0/1). Reject the
        // degenerate few-wide-substrings case rather than OOM.
        let max_width = bounds.iter().map(|&(_, w)| w).max().unwrap_or(0);
        assert!(
            max_width <= MAX_SUBSTRING_BITS,
            "m={m} gives a {max_width}-bit substring; 128/m must be \u{2264} {MAX_SUBSTRING_BITS} bits (use m \u{2265} 6)"
        );
        let mut tables = Vec::with_capacity(m);
        for (shift, width) in bounds {
            let mask: u128 = if width == 128 { u128::MAX } else { (1u128 << width) - 1 };
            let nbuckets = 1usize << width;

            // counting sort of positions by substring value
            let mut dir = vec![0u32; nbuckets + 1];
            for &code in &codes {
                let s = ((code >> shift) & mask) as usize;
                dir[s + 1] += 1;
            }
            for b in 1..=nbuckets {
                dir[b] += dir[b - 1];
            }
            let mut positions = vec![0u32; n];
            let mut cursor = dir.clone();
            for (i, &code) in codes.iter().enumerate() {
                let s = ((code >> shift) & mask) as usize;
                positions[cursor[s] as usize] = i as u32;
                cursor[s] += 1;
            }
            tables.push(Table { shift, width, mask, dir, positions });
        }
        MihStore { codes, ids, tables, m }
    }

    pub fn len(&self) -> usize {
        self.codes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }
    pub fn m(&self) -> usize {
        self.m
    }

    /// All payload ids whose signature is within Hamming distance `r` of `query`.
    /// Exact: every true neighbour is returned, and every returned id is
    /// verified within `r`.
    pub fn query(&self, query: u128, r: u32) -> Vec<u64> {
        self.query_with_dist(query, r).into_iter().map(|(id, _)| id).collect()
    }

    /// Like `query`, but returns `(id, distance)` — used when the caller wants
    /// the closest library version, not just presence.
    pub fn query_with_dist(&self, query: u128, r: u32) -> Vec<(u64, u32)> {
        let sub_r = r / self.m as u32; // pigeonhole per-substring radius

        // Gather candidate positions across all substring tables.
        let mut candidates: Vec<u32> = Vec::new();
        let mut flips: Vec<u32> = Vec::new();
        for table in &self.tables {
            let qsub = table.substring(query);
            enumerate_within(table.width, sub_r, &mut flips);
            for &f in &flips {
                let bucket = (qsub ^ f) as usize;
                let lo = table.dir[bucket] as usize;
                let hi = table.dir[bucket + 1] as usize;
                candidates.extend_from_slice(&table.positions[lo..hi]);
            }
        }

        // Dedup, then verify the full 128-bit distance.
        candidates.sort_unstable();
        candidates.dedup();
        let mut out = Vec::new();
        for &pos in &candidates {
            let p = pos as usize;
            let dist = (self.codes[p] ^ query).count_ones();
            if dist <= r {
                out.push((self.ids[p], dist));
            }
        }
        out
    }
}

/// Suggested substring count: `m ≈ b / log2(N)` (Norouzi et al. §4), clamped so
/// the per-table directory stays small. For b=128 and N in the millions this
/// lands around 6–8.
pub fn suggest_m(n: usize) -> usize {
    if n < 2 {
        return 6; // smallest valid m for 128-bit codes (widest substring ≤ 22 bits)
    }
    let log2n = (usize::BITS - (n - 1).leading_zeros()) as usize;
    // Lower bound 6 keeps the widest substring ≤ 22 bits (see MAX_SUBSTRING_BITS).
    (128 / log2n.max(1)).clamp(6, 16)
}

/// Bit (shift, width) of each of `m` near-equal substrings of a 128-bit code.
/// The first `128 % m` substrings are one bit wider.
fn substring_bounds(m: usize) -> Vec<(u32, u32)> {
    let base = 128 / m;
    let extra = 128 % m;
    let mut out = Vec::with_capacity(m);
    let mut shift = 0u32;
    for i in 0..m {
        let width = (base + if i < extra { 1 } else { 0 }) as u32;
        out.push((shift, width));
        shift += width;
    }
    out
}

/// Fill `out` with every bitmask of `width` bits whose popcount is `<= radius`
/// (i.e. the query substring's Hamming neighbourhood). For `radius == 0` this is
/// just `[0]` — an exact bucket lookup.
fn enumerate_within(width: u32, radius: u32, out: &mut Vec<u32>) {
    out.clear();
    out.push(0);
    if radius == 0 {
        return;
    }
    let w = width as usize;
    // masks with exactly k set bits, for k = 1..=radius
    let mut combo = Vec::new();
    for k in 1..=radius as usize {
        combo.clear();
        combos(w, k, 0, 0u32, &mut combo, out);
    }
}

fn combos(w: usize, k: usize, start: usize, acc: u32, _combo: &mut Vec<usize>, out: &mut Vec<u32>) {
    if k == 0 {
        out.push(acc);
        return;
    }
    // need k more bits from positions [start, w)
    for pos in start..=(w - k) {
        combos(w, k - 1, pos + 1, acc | (1u32 << pos), _combo, out);
    }
}
