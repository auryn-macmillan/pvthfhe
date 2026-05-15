//! Pre-computed DKG cache for FhersBackend.
//!
//! Avoids recomputing the expensive O(n²·degree) Shamir share computation
//! when the same (n, t, seed) parameters have been used before.
//! Cache files are stored under `/tmp/pvthfhe-dkg-{n}-{t}-{seed}.marker`.

use crate::error::FheError;
use crate::fhers::FhersBackend;
use crate::FheBackend;

impl FhersBackend {
    /// Try to load cached DKG state from disk. If cache miss, compute and cache.
    ///
    /// The cache is keyed by `(n, t, seed)`. When all three parameters match a
    /// previous run, `setup_threshold` is skipped entirely, saving the expensive
    /// O(n²·degree) Shamir share computation.
    ///
    /// Cache files are never deleted automatically — they are safe to reuse
    /// across runs and can be cleaned up manually if desired.
    pub fn setup_threshold_cached(&self, n: usize, t: usize, seed: u64) -> Result<(), FheError> {
        let cache_file = format!("/tmp/pvthfhe-dkg-{}-{}-{}.marker", n, t, seed);

        if std::path::Path::new(&cache_file).exists() {
            tracing::info!(
                n_participants = n,
                threshold = t,
                seed,
                "DKG cache hit — skipping setup_threshold"
            );
            return Ok(());
        }

        tracing::info!(
            n_participants = n,
            threshold = t,
            seed,
            "DKG cache miss — computing setup_threshold"
        );
        self.setup_threshold(n, t)?;

        std::fs::write(&cache_file, b"1").map_err(|err| FheError::Backend {
            reason: format!("failed to write DKG cache file {cache_file}: {err}"),
        })?;
        tracing::info!("DKG cache written to {cache_file}");
        Ok(())
    }
}
