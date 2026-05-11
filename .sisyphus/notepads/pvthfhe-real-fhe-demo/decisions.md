# Decisions
## [2026-05-05]
- Backend: gnosisguild/fhe.rs locked at rev 5f24d0b62a7329b789db07a065b68accd614a47b
- dep strategy: direct composition of fhe::mbfv + fhe::trbfv (not e3-trbfv wrapper) - avoids Cipher transitive dep
