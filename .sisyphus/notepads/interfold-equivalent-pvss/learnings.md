# Learnings — interfold-equivalent-pvss

## 2026-05-11 — Batch A.3: Freeze Target Relations in nizk-construction.md

### Document structure
- `nizk-construction.md` follows a clear pattern: status line → scope → context → candidates → comparison matrix → recommendation → integration sketch → open questions → references. Each major section is delimited by `---`.
- The existing R3.1 and R3.2 relation descriptions (lines 18-34) served as the template for the R3.4 relation descriptions, using a prose-heavy format with bold labels and inline code blocks.

### Domain separator conventions
- Codebase uses `"pvthfhe-{layer}-{purpose}-v{n}"` convention (e.g., `"pvthfhe-pvss-share-encryption-v2"`, `"pvthfhe-cyclo-fs-v1"`).
- The new R3.4 DS strings use `"pvthfhe-R-{relation-name}-v1"` pattern, consistent with the `"pvthfhe-"` prefix convention.
- The `"-R-"` infix distinguishes these as relation-bound domain separators rather than implementation-bound ones.

### Mapping to Interfold
- The five relations map to Interfold C0-C7 as follows:
  - R3.4.1 → C0 (pk) + C3 (ShareEncryption), batched for sk/e_sm
  - R3.4.2 → C2a (SkShareComputation) + C2b (ESmShareComputation), batched
  - R3.4.3 → C4 (DkgShareDecryption) + C5 (PkAggregation), two-track
  - R3.4.4 → C6 (ThresholdShareDecryption), committed-smudge extension
  - R3.4.5 → C7 (DecryptedSharesAggregation)
- C1 (PkGeneration) is captured across R3.4.2 (secret contributions) and R3.4.3 (aggregation).

### Editing approach
- Used two edit operations: one for the status line, one for the bulk content insertion before `## References`.
- The insertion anchor used a 4-line unique context snippet spanning the last paragraph of "Open Questions", the section separator, and the start of References.
- Nested the content within the existing `---` separator structure to maintain formatting consistency.
- File grew from 493 to 670 lines (177 lines added).

### Style notes
- The existing document uses em dashes (`—`) in prose (e.g., status line, description fields). New content followed this convention for consistency.
- All field descriptions use the pattern: `` `field_name: Type` — description ``.
- Commitment bindings use numbered lists for verificaton check descriptions.
