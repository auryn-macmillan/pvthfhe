
## G.29 Domain Constants Audit (2026-05-18)

### Key Findings
- Noir defines 6 `DOMAIN_*` constants (values 1-6) in `circuits/protocol_constants/src/lib.nr`
- Rust `full_pipeline.rs` correctly uses domain 1 (vector_hash_8) and domain 6 (bind_8_with_domain_native) for `aggregator_final`
- Domains 2-5 are Noir-internal (used within `decrypt_share` circuit to compute commitment bindings)
- `witness_gen.rs` uses a rolling digest (DIGEST_DOMAIN=987654321) instead of Poseidon — stale/legacy code for deferred `noir_decrypt_share` phase
- Rust `pvthfhe-domain-tags` crate uses STRING-based tags — separate system from numeric Poseidon domain tags
- No fixes needed for active code paths

## G.28: Robust Secret Sharing documentation (2026-05-18)

### What was done
- Added `\subsection{Robust Secret Sharing}` to `paper/main.tex` in the Security Analysis section, after the Fiat-Shamir subsection and before Implementation and Evaluation.
- Added `@inproceedings{fehr2019rss}` to `paper/bib.bib` citing Fehr-Yuan EUROCRYPT 2019.

### Insertion point
- Line 546 of `paper/main.tex` (between Fiat-Shamir subsection end at line 545 and `\section{Implementation and Evaluation}`).

### Content summary
- Current approach: Lagrange interpolation over t shares, error detection via plaintext decode failure.
- Limitation: Cannot identify WHICH party submitted the bad share.
- Solution referenced: VSS/RSS with cheater identification for t < n/2; cites Fehr-Yuan 2019.
- Status: Deferred to future work; misbehavior detection via retry with subset selection is sufficient for honest-majority protocols.

### Verification
- `just paper-gate` passed: all 7 checks (claims-table, theorem-consistency, figures, internal-reviews, external-reviews, submission-bundle).

### Bib entry details
- Key: `fehr2019rss`
- Volume: LNCS 11477 (EUROCRYPT 2019, Part II)
- DOI: 10.1007/978-3-030-17656-3_6
