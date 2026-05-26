## G.11 - Duplicate party_id check

**Pattern**: Used `replaceAll: true` in edit tool to add duplicate check in 3 functions at once. The 3 functions (`aggregate_decrypt`, `aggregate_decrypt_with_poly`, `aggregate_decrypt_raw_result_poly`) all had identical range-check blocks.

**Lesson**: When multiple functions share identical code blocks that need the same fix, `replaceAll: true` is efficient. Verify with grep that the matched pattern doesn't appear elsewhere (the 4th `for share in shares` at line 675 is in `aggregate_keygen` which has different body content).

**Location of changes**:
- Line 1207: `aggregate_decrypt`
- Line 1471: `aggregate_decrypt_with_poly`
- Line 1608: `aggregate_decrypt_raw_result_poly`
