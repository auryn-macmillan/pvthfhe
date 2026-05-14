# CCS Encoding Design Doc — Cyclo LatticeFold+ Adapter (P2-M1.1)

**Status**: Draft  
**Date**: 2026-05-14  
**Plan**: `.sisyphus/plans/p2-m1-cyclo-ccs-adapter.md`  
**Purpose**: Document the exact CCS constraint matrix encoding the frozen P1 verifier equation over the Cyclo commitment ring, enabling LatticeFold+ folding of per-share witness instances.

---

## §1 — Equation Recap

### 1.1 P1 Verifier Equation (Frozen)

The P1 sigma protocol verifier (implemented in `crates/pvthfhe-nizk/src/sigma.rs`,
`verify()` lines 180–236) checks the following algebraic equation over the
RLWE ring $R_Q = \mathbb{Z}_Q[X]/(X^{8192}+1)$:

$$c \cdot z_s + z_e \equiv t + ch \cdot d_i \pmod{Q}$$

Where:

| Symbol | Description | Domain |
|--------|-------------|--------|
| $c$ | Ciphertext polynomial | $R_Q$, N=8192 |
| $d_i$ | Per-party decryption share | $R_Q$, N=8192 |
| $ch$ | Fiat-Shamir challenge polynomial | $\{0,1\}^{8192}$ (binary coefficients) |
| $t$ | Mask commitment $t = c \cdot y_s + y_e$ | $R_Q$, N=8192 |
| $z_s$ | Response $z_s = y_s + ch \cdot s_i$ (over $\mathbb{Z}^N$) | Integer polynomial |
| $z_e$ | Response $z_e = y_e + ch \cdot e_i$ (over $\mathbb{Z}^N$) | Integer polynomial |
| $s_i$ | Secret key share | $\{-1,0,1\}^{8192}$ (ternary) |
| $e_i$ | Error term | $\mathbb{Z}^{8192}$, $\|e_i\|_\infty \leq 16$ |

### 1.2 Projection to Cyclo Commitment Ring

For CCS encoding, the equation is projected onto the Cyclo commitment ring via
the $\theta_2$ map (see `cyclo-digest.md` §6.2):

$$R_{q\_commit} = \mathbb{Z}_{q\_commit}[X]/(X^{256}+1)$$

With locked parameters:

| Parameter | Value | Source |
|-----------|-------|--------|
| Ring degree $\phi$ | 256 | `spec-real-p2p3.md` §4.1 |
| Commitment modulus $q_{commit}$ | 562,949,953,438,721 ($\approx 2^{50}$) | `spec-real-p2p3.md` §4.1 addendum |
| Challenge $c$ | $\{-1, 0, 1\}$ (ternary scalar, not polynomial) | `spec-real-p2p3.md` §4.1 |
| Challenge space size | $3$ | Biased ternary, $p=1/3$ |

The simplified verifier equation (per coefficient, over $R_{q\_commit}$):

$$c \cdot z_s + z_e - t - c \cdot d_i \equiv 0 \pmod{q\_commit}$$

Equivalently:

$$c \cdot z_s + z_e \equiv t + c \cdot d_i \pmod{q\_commit}$$

**Witness** (private): $w = (s, e)$ — the secret key and error polynomials.

**Public statement** (instances): $x = (t, d_i, c)$ — the commitment, decryption share,
and challenge.

---

## §2 — CCS Variable Vector $z$

### 2.1 Encoding Strategy

The CCS variable vector operates over the BN254 scalar field
$\mathbb{F}_p \approx 2^{254}$. Each polynomial coefficient in $R_{q\_commit}$ is
embedded as a separate $\mathbb{F}_p$ element. The ring structure is imposed
externally by the constraint matrices, not by the variable layout.

### 2.2 Variable Enumeration

The variable vector $z \in \mathbb{F}_p^{1025}$ contains 1025 entries:

| Index Range | Count | Name | Description | Visibility |
|-------------|-------|------|-------------|------------|
| $0 \ldots 255$ | 256 | $s[0..255]$ | Secret key coefficients in $\{-1, 0, 1\}$ | Witness (private) |
| $256 \ldots 511$ | 256 | $e[0..255]$ | Error coefficients, $\|e[i]\| \leq 16$ | Witness (private) |
| $512 \ldots 767$ | 256 | $z_s[0..255]$ | Masked response $z_s = y_s + c \cdot s_i$ per coefficient | Mixed (response) |
| $768 \ldots 1023$ | 256 | $z_e[0..255]$ | Masked error response $z_e = y_e + c \cdot e_i$ per coefficient | Mixed (response) |
| $1024$ | 1 | $1$ | Constant $1$ (auxiliary for CCS linearization) | Public constant |

**Total**: $4 \times 256 + 1 = \mathbf{1025}$ variables.

### 2.3 Variable Layout (Tabular)

```
z layout (1025 Fr elements, 0-indexed):
┌──────────────────────────────────────────────────────────────┐
│ s[0] .. s[255] │ e[0] .. e[255] │ z_s[0] .. z_s[255] │ ...  │
│   (0–255)      │    (256–511)   │     (512–767)       │      │
├────────────────┼────────────────┼─────────────────────┼──────┤
│ z_e[0] .. z_e[255] │         1        │                    │
│    (768–1023)       │      (1024)      │                    │
└─────────────────────┴─────────────────┴────────────────────┘
```

### 2.4 Coefficient Embedding

Each integer coefficient is represented as a BN254 $\mathbb{F}_p$ field element:

- **Small values** ($\|v\| \leq 2^{50}$): Represented directly, well within $\mathbb{F}_p \approx 2^{254}$.
- **Negative values**: Represented as $v \bmod q_{commit}$ (the commitment ring modulus) or as $\mathbb{F}_p$ values via modular embedding.
- **Constant $1$**: The field element `1` in $\mathbb{F}_p$.

No overflow concerns exist because $q_{commit} \approx 2^{50} \ll \mathbb{F}_p \approx 2^{254}$.

---

## §3 — CCS Matrices

### 3.1 CCS Three-Matrix Formalism

The CCS (Customizable Constraint System) relation is (from Cyclo ePrint 2026/359 §3):

$$(M_1 \cdot z) \odot (M_2 \cdot z) = M_3 \cdot z$$

where $\odot$ denotes element-wise (Hadamard) multiplication, and $M_1, M_2, M_3 \in \mathbb{F}_p^{m \times n}$.

### 3.2 Encoding Linear Constraints

The P1 verifier equation is **purely linear** in the variables (challenge $c$ is a
public constant, not a variable). To encode a linear equation $L(z) = R$ (where
$R$ is a vector of public constants) in CCS, we use the **constant-1 trick**:

1. Include auxiliary variable $z[1024] = 1$ in the witness vector.
2. Set $M_1$ to encode the linear transformation $L(z)$ applied to the variables.
3. Set $M_2$ to select the constant $1$ from $z$ (so $M_2 \cdot z = \vec{1}$).
4. Set $M_3$ to embed the public constant $R$: $M_3[i][1024] = R[i]$, so $M_3 \cdot z = R$.

Then the CCS relation simplifies to:

$$L(z) \odot \vec{1} = R \quad\Longrightarrow\quad L(z) = R$$

### 3.3 Matrix Specifications

**Dimensions**: All three matrices share dimensions $m \times n = 256 \times 1025$.

#### 3.3.1 Matrix $M_1$ — Encodes $c \cdot z_s + z_e$ (the variable side)

For each constraint row $i \in \{0, \ldots, 255\}$, $M_1$ selects the $z_s$ and
$z_e$ coefficients weighted by the challenge:

$$M_1[i][j] = \begin{cases}
c      & \text{if } j = 512 + i \quad\text{(selects } z_s[i]\text{, weighted by challenge } c) \\
1      & \text{if } j = 768 + i \quad\text{(selects } z_e[i]\text{)} \\
0      & \text{otherwise}
\end{cases}$$

**Interpretation**: $(M_1 \cdot z)[i] = c \cdot z_s[i] + z_e[i]$ for each coefficient $i$.

**Sparsity**: Exactly 2 non-zero entries per row. Total non-zeros: $2 \times 256 = 512$.
Remaining $256 \times 1025 - 512 = 261,888$ entries are zero.

#### 3.3.2 Matrix $M_2$ — Selects the constant $1$

$$M_2[i][j] = \begin{cases}
1 & \text{if } j = 1024 \quad\text{(selects the constant } 1\text{)} \\
0 & \text{otherwise}
\end{cases}$$

**Interpretation**: $(M_2 \cdot z)[i] = 1$ for every row. This reduces the Hadamard
product to the identity, converting the CCS relation into the linear equation.

**Sparsity**: Exactly 1 non-zero entry per row. Total non-zeros: $256$.

#### 3.3.3 Matrix $M_3$ — Embeds the public constant $t + c \cdot d_i$

Public values $t[i]$ (mask commitment coefficient) and $d_i[i]$ (decryption share
coefficient) are embedded as matrix entries multiplied by the constant-1 variable:

$$M_3[i][j] = \begin{cases}
t[i] + c \cdot d_i[i] \pmod{q_{commit}} & \text{if } j = 1024 \quad\text{(constant times public value)} \\
0 & \text{otherwise}
\end{cases}$$

**Interpretation**: $(M_3 \cdot z)[i] = t[i] + c \cdot d_i[i]$ (the public-side constant).

**Note**: The values $t[i] + c \cdot d_i[i]$ are computed over $\mathbb{Z}_{q_{commit}}$
and then embedded into $\mathbb{F}_p$.

**Sparsity**: Exactly 1 non-zero entry per row. Total non-zeros: $256$.

### 3.4 Constraint Correctness Audit

For row $i$, the CCS relation enforces:

$$\begin{aligned}
(M_1 \cdot z)[i] &= c \cdot z_s[i] + z_e[i] \\
(M_2 \cdot z)[i] &= 1 \\
(M_3 \cdot z)[i] &= t[i] + c \cdot d_i[i]
\end{aligned}$$

Applying the CCS Hadamard check:

$$(M_1 \cdot z)[i] \odot (M_2 \cdot z)[i] = (M_3 \cdot z)[i]$$

$$(c \cdot z_s[i] + z_e[i]) \cdot 1 = t[i] + c \cdot d_i[i]$$

$$c \cdot z_s[i] + z_e[i] = t[i] + c \cdot d_i[i]$$

$$c \cdot z_s[i] + z_e[i] - t[i] - c \cdot d_i[i] \equiv 0 \pmod{q_{commit}} \quad\checkmark$$

### 3.5 Treatment of $s$ and $e$ in the Base Encoding

The witness variables $s[0..255]$ and $e[0..255]$ (indices 0–511) are **not**
constrained by the base P1 verifier equation encoded here. They are included in
the variable vector $z$ for composition with additional constraints added in
later phases:

| Constraint | Phase | Encodes |
|------------|-------|---------|
| RLWE relation $d_i = c \cdot s_i + e_i$ | M1.3 | Row augmentation: M₁, M₂, M₃ get additional rows encoding $c \cdot s_i \equiv d_i - e_i$ (see `ccs_rlwe.rs`) |
| $\ell_\infty$ norm bounds $\|e_i\|_\infty \leq 16$, $\|s_i\|_\infty \leq 1$ | M2 | Range-check rows added to the matrix |
| Ajtai commitment check $u = A \cdot w$ | M4 | Ring multiplication rows encoding $\text{Com}_{Ajtai}(s, e)$ |

In the $M_1$ matrix as defined above, rows and columns corresponding to $s$ and $e$
contain zeros — they are present but unconstrained in the base encoding.

### 3.6 Visual Matrix Structure

```
M₁ (256 × 1025):
         │← s:256 →│← e:256 →│←── z_s:256 ──→│←── z_e:256 ──→│ 1│
         │·········│·········│c in diag       │1 in diag       │0 │
   Row 0 │  0…0    │  0…0    │ c  0  0 … 0    │ 1  0  0 … 0    │ 0 │
   Row 1 │  0…0    │  0…0    │ 0  c  0 … 0    │ 0  1  0 … 0    │ 0 │
    …    │   …     │   …     │    …           │    …           │…  │
 Row 255 │  0…0    │  0…0    │ 0  0 … 0  c    │ 0  0 … 0  1    │ 0 │

M₂ (256 × 1025):
         │← s:256 →│← e:256 →│← z_s:256 →│← z_e:256 →│ 1│
         │  0…0    │  0…0    │  0…0      │  0…0      │ 1 │  (every row identical)

M₃ (256 × 1025):
         │← s:256 →│← e:256 →│← z_s:256 →│← z_e:256 →│ 1              │
   Row 0 │  0…0    │  0…0    │  0…0      │  0…0      │ t[0]+c·d_i[0]  │
   Row 1 │  0…0    │  0…0    │  0…0      │  0…0      │ t[1]+c·d_i[1]  │
    …    │   …     │   …     │   …       │   …       │      …         │
 Row 255 │  0…0    │  0…0    │  0…0      │  0…0      │ t[255]+c·d_i[255]│
```

---

## §4 — Constraint Count

### 4.1 Dimensions

| Quantity | Value | Formula |
|----------|-------|---------|
| Constraints $m$ (rows) | **256** | $N_{commit}$ — one per ring coefficient |
| Variables $n$ (columns) | **1025** | $4 \cdot N_{commit} + 1$ |
| Matrix entries total (per matrix) | **262,400** | $m \times n = 256 \times 1025$ |
| Non-zero entries in $M_1$ | **512** | $2 \times 256$ (two per row) |
| Non-zero entries in $M_2$ | **256** | $1 \times 256$ (one per row) |
| Non-zero entries in $M_3$ | **256** | $1 \times 256$ (one per row) |
| Overall sparsity | **99.87%** | $(512+256+256) / (3 \times 256 \times 1025)$ |

### 4.2 Constraint Decomposition

Each constraint row $i$ verifies one coefficient of the polynomial equation
$c \cdot z_s + z_e - t - c \cdot d_i \equiv 0 \pmod{q_{commit}}$.

The constraints are:

| Constraint Type | Rows | What It Enforces |
|-----------------|------|-----------------|
| P1 verifier equation (per coefficient) | 0–255 | $c \cdot z_s[i] + z_e[i] = t[i] + c \cdot d_i[i]$ |
| **Total (base encoding)** | **256** | — |
| RLWE relation (future, M1.3) | +256 | $c \cdot s_i[i] = d_i[i] - e_i[i]$ (per coefficient) |
| Norm bounds (future, M2) | +512 | $\|e_i[i]\| \leq 16$, $\|s_i[i]\| \leq 1$ per coefficient |
| Ajtai commitment (future, M4) | +TBD | Ring multiplication constraints |

### 4.3 Ring vs. Field: Coefficient-Wise Independence

In this base encoding (before adding ring-multiplication constraints), each
coefficient is verified independently. There are **no cross-coefficient matrix
entries** — the matrix is block-diagonal in the coefficient dimension. This is
possible only because:

1. The challenge $c$ is a **scalar field constant**, not a polynomial variable.
2. The equation involves only coefficient-wise operations (scalar multiplication and addition).
3. No polynomial multiplication (convolution) appears in the base equation.

This coefficient-wise independence means the 256 constraints are **embarrassingly
parallel** — each can be verified independently without NTT or convolution.

---

## §5 — Ring Multiplication Encoding

### 5.1 Ternary Challenge: Conditional Scalar Multiplication

The challenge $c \in \{-1, 0, 1\}$ is treated as a **public field constant**, not
a CCS variable. The multiplication $c \cdot z_s$ is therefore a **scalar**
multiplication, not a ring (polynomial) multiplication.

For the three possible challenge values:

| $c$ | $c \cdot z_s[i]$ | Arithmetic | CCS Matrix Effect |
|-----|-------------------|------------|-------------------|
| $+1$ | $z_s[i]$ | Identity | $M_1[i][512+i] = 1$ |
| $-1$ | $-z_s[i]$ | Negation | $M_1[i][512+i] = -1 \equiv q_{commit}-1 \pmod{q_{commit}}$ |
| $0$ | $0$ | Zero | $M_1[i][512+i] = 0$ (constraint becomes $z_e[i] = t[i]$) |

These are implemented as **conditional constant values** in the $M_1$ matrix,
avoiding any CCS variable representing the challenge itself. The matrix is
parameterized by the public challenge value; a new matrix instance is produced
for each proof session (since $c$ varies per session via Fiat-Shamir).

### 5.2 No Polynomial Multiplication in the Base Equation

The base P1 verifier equation contains **only scalar** (coefficient-wise)
multiplication. There is no true polynomial multiplication (convolution modulo
$X^{256}+1$) in the equation $c \cdot z_s + z_e = t + c \cdot d_i$ because:

- $c$ is a scalar constant, not a polynomial.
- All operations are per-coefficient: addition, subtraction, scalar multiplication.

Consequently, the ring structure $R_{q\_commit} = \mathbb{Z}_{q\_commit}[X]/(X^{256}+1)$
**does not affect** the base CCS encoding. The 256 coefficients are treated as
independent field elements, and the constraint matrices have block-diagonal
structure.

### 5.3 When Ring Multiplication Becomes Necessary

True polynomial multiplication over the commitment ring arises when composing
the base equation with additional constraints:

| Composition | Multiplication Type | Phase |
|-------------|-------------------|-------|
| Ajtai commitment $u = A \cdot w$ over $R_{q\_commit}$ | Ring element (polynomial) multiplication modulo $X^{256}+1$ | M4 |
| Norm range checks over ring extensions | Extension-field arithmetic ($e=2$) | M3 |
| Accumulator cross-folding | Ring multiplication with accumulator coefficients | M5 |

When these are added, the CCS matrices must grow to include rows encoding
polynomial convolution operations. The convolution $a \ast b \bmod X^{256}+1$
requires $256$ multiplications and $255$ subtractions per coefficient (for
naive $O(N^2)$ implementation), producing $256^2 = 65,\!536$ scalar
multiplications per ring product. Each scalar multiplication becomes **one
non-zero CCS matrix entry** when the ring multiplication is encoded as a
linear constraint (since one polynomial is a constant/known quantity).

### 5.4 NTT vs. Direct Convolution (Forward-Looking)

For polynomial multiplication in the commitment ring:

| Method | Operations per ring multiply | CCS non-zero entries per constraint | Phase |
|--------|---------------------------|-------------------------------------|-------|
| Coefficient-wise (no ring op) | $O(1)$ per coefficient | 2 per row | M1 (current) |
| Direct convolution $O(N^2)$ | 65,536 multiplications | 65,536 per ring product row | M4 (acceptable for φ=256) |
| NTT over $\mathbb{F}_p$ | $O(N \log N) \approx 2048$ ops | Depends on NTT-friendly modulus | M4+ (optimization) |

For $N=256$, the $O(N^2)$ direct convolution is acceptable for M4
($65,\!536 \ll 2^{20}$), avoiding the need for NTT-friendly moduli or
complex constraint encoding.

---

## §6 — Encoding Summary

### 6.1 Data Flow

```
P1 Sigma Protocol                    CCS Matrices
┌──────────────┐                    ┌─────────────────────┐
│ Public:      │                    │ M₁ (256×1025):      │
│  t[0..255]   │────────────────────│  row i, cols 512+i: │
│  d_i[0..255] │    Public consts   │    = c (challenge)  │
│  c ∈ {-1,0,1}│    embedded in     │  row i, cols 768+i: │
│              │    M₃              │    = 1              │
│ Witness:     │                    │                     │
│  z_s[0..255] │──── Witness ──────▶│ M₂ (256×1025):      │
│  z_e[0..255] │    placed in       │  all rows, col 1024:│
│  s[0..255]   │    z vector        │    = 1              │
│  e[0..255]   │                    │                     │
│              │                    │ M₃ (256×1025):      │
│              │                    │  row i, col 1024:   │
│              │                    │    = t[i]+c·d_i[i]  │
└──────────────┘                    └─────────────────────┘
                                          │
                                          ▼
                              CCS Relation:
                              (M₁·z) ⊙ (M₂·z) == M₃·z
                              256 constraint checks
```

### 6.2 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| coefficient-wise encoding (not ring-element encoding) | Allows scalar-field CCS over $\mathbb{F}_p$ without polynomial multiplication; simple verifier logic |
| constant-1 variable trick for linear constraints | Standard CCS technique to encode $L(z) = R$ using Hadamard identity |
| challenge $c$ embedded in matrix coefficients | Avoids challenge-as-variable; keeps constraint count low; ternary set enables simple conditional weights |
| $s$ and $e$ in variable vector but unconstrained | Enables seamless composition with RLWE and norm-bound constraints in later phases without re-indexing |
| 256 rows = one per coefficient | Matches ring degree; each constraint isolates one coefficient position; embarrassingly parallel verification |

### 6.3 Relation to Existing Code

| Code Artifact | File | Relationship |
|---------------|------|-------------|
| CCS satisfiability check | `crates/pvthfhe-cyclo/src/ccs_encode.rs:check_satisfiability_rq()` | Generic CCS verifier accepting 3-matrix instances |
| RLWE CCS encoder | `crates/pvthfhe-cyclo/src/ccs_rlwe.rs:encode_rlwe_share_relation()` | Encodes $d_i = c \cdot s_i + e_i$ — to be composed with this P1 verifier encoding |
| Sigma protocol verifier | `crates/pvthfhe-nizk/src/sigma.rs:verify()` | Source of the exact P1 equation being encoded |
| CCS test suite | `crates/pvthfhe-cyclo/tests/ccs_rlwe_relation.rs` | Integration tests for CCS satisfiability |

---

## §7 — References

| Source | Description |
|--------|-------------|
| `cyclo-digest.md` §4.1, §6.2 | Cyclo folding relation and ring parameters |
| `spec-real-p2p3.md` §4.1 | Locked Cyclo parameters ($\phi=256$, $q_{commit} \approx 2^{50}$, ternary challenge) |
| `spec-real-p2p3.md` §4.2 | Sonobe substitute context |
| `spec-real-p2p3.md` §3.1 | P1 statement and witness shape |
| `spec-real-p2p3.md` §3.2 | Cyclo-companion Ajtai NIZK construction summary |
| `fold-construction.md` §2.3 | CCS encoder role under Sonobe substitution |
| `fold-construction.md` §4.2 | v2 migration surface |
| `p2-m1-cyclo-ccs-adapter.md` | Parent plan (P2-M1) |
| `ccs_rlwe.rs` | Existing CCS RLWE relation encoding (for future composition) |
| `sigma.rs:verify()` | P1 sigma protocol verifier (source of equation) |
| Cyclo ePrint 2026/359 §3 | CCS constraint system definition |
| `ccs-full-matrix` notepad | Implementation learnings for 3-matrix CCS format |

---

*Document version*: 1.0  
*Next phase*: P2-M1.2 — Implement ring arithmetic in CCS (`crates/pvthfhe-aggregator/src/folding/ccs_adapter.rs`)
