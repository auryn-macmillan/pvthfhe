## 2026-05-07
- Preserve the existing generic validation path for `n == 0`, `t == 0`, and `t > n`, but split out `n > 255` so the backend can explain the protocol limit explicitly.
