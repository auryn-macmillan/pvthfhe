## [2026-05-02] Task: T1
- Initial LSP diagnostics could not run because rust-analyzer and biome were not installed in the environment.
- rust-analyzer was installed via `rustup component add rust-analyzer`; re-run diagnostics after the tool becomes available to confirm cleanliness.
