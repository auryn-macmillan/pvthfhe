# Decisions — Round 6 Adversarial Remediation, Batch B

## Documentation-only for F4-F6
Per plan, F4 (e_i=0), F5 (circular pvss_commitment), and F6 (caller-only binding)
are documented as defense-in-depth commentary rather than code fixes. The actual
cryptographic soundness comes from independent layers (BFV sigma proof, D2 binding,
relation binding). These comments inform future auditors of known trade-offs.
