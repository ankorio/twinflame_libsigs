//! Python binding (feature `python`) — exposes the native MIH store to
//! twinflame. 128-bit signatures cross the boundary as Python ints (pyo3 maps
//! `u128` to/from arbitrary-precision `int`), matching twinflame's
//! `Signature.combined`.
//!
//! Build: `maturin develop --features python` (or `--release`). Import as
//! `tfls_mih`:
//!
//! ```python
//! from tfls_mih import MihStore, suggest_m
//! store = MihStore.build([(sig0, 0), (sig1, 1)], suggest_m(2))
//! store.query(query_sig, 12)          # -> [payload ids within Hamming 12]
//! ```

use pyo3::prelude::*;

use crate::{suggest_m as core_suggest_m, Entry, MihStore};

#[pyclass(name = "MihStore", module = "tfls_mih")]
pub struct PyMihStore {
    inner: MihStore,
}

#[pymethods]
impl PyMihStore {
    /// Build from a list of `(signature:int, payload_id:int)` pairs. `m` is the
    /// substring count — use `suggest_m(len(entries))` unless tuning.
    #[staticmethod]
    fn build(entries: Vec<(u128, u64)>, m: usize) -> Self {
        let ents: Vec<Entry> = entries
            .into_iter()
            .map(|(code, id)| Entry { code, id })
            .collect();
        PyMihStore { inner: MihStore::build(&ents, m) }
    }

    /// Payload ids whose signature is within Hamming distance `r` of `query`.
    fn query(&self, query: u128, r: u32) -> Vec<u64> {
        self.inner.query(query, r)
    }

    /// `(payload_id, distance)` pairs within `r` — for closest-version lookups.
    fn query_with_dist(&self, query: u128, r: u32) -> Vec<(u64, u32)> {
        self.inner.query_with_dist(query, r)
    }

    #[getter]
    fn m(&self) -> usize {
        self.inner.m()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }
}

#[pyfunction]
#[pyo3(name = "suggest_m")]
fn py_suggest_m(n: usize) -> usize {
    core_suggest_m(n)
}

#[pymodule]
fn tfls_mih(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyMihStore>()?;
    m.add_function(wrap_pyfunction!(py_suggest_m, m)?)?;
    m.add("MAX_SUBSTRING_BITS", crate::MAX_SUBSTRING_BITS)?;
    Ok(())
}
