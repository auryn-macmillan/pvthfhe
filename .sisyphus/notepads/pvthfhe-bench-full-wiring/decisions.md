# Decisions — pvthfhe-bench-full-wiring

## 2026-05-07 Task A1 — schema initialization choice

- Kept `E2eTimings::new(...)` responsible for emitting a fully populated zeroed `E2ePhases` tree so downstream JSON consumers can rely on stable presence of all required phase keys before timing wiring lands.
