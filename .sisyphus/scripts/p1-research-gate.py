#!/usr/bin/env python3
# pyright: reportImplicitRelativeImport=false, reportUnknownVariableType=false
"""p1-research-gate gate."""
import argparse
import importlib.util
import os
import re
from decimal import Decimal, InvalidOperation
from typing import Callable, cast

RunGate = Callable[[str, dict[str, Callable[[], tuple[bool, list[str]]]], argparse.Namespace], None]

_GATE_UTILS_PATH = os.path.join(os.path.dirname(__file__), '_gate_utils.py')
_GATE_UTILS_SPEC = importlib.util.spec_from_file_location('_gate_utils', _GATE_UTILS_PATH)
if _GATE_UTILS_SPEC is None or _GATE_UTILS_SPEC.loader is None:
    raise ImportError(f"unable to load gate utilities from {_GATE_UTILS_PATH}")
_gate_utils = importlib.util.module_from_spec(_GATE_UTILS_SPEC)
_GATE_UTILS_SPEC.loader.exec_module(_gate_utils)
run_gate = cast(RunGate, getattr(_gate_utils, 'run_gate'))

GATE_NAME = "p1-research-gate"

ARTIFACTS = ['.sisyphus/research/lit-survey.md']
PRIOR_ART_MATRIX = '.sisyphus/research/p1/prior-art.md'
THREAT_MODEL_PATH = '.sisyphus/research/p1/threat-model.md'
THEOREM_INVENTORY_PATH = 'docs/security-proofs/p1/theorem-inventory.md'
OBLIGATIONS_PATH = 'docs/security-proofs/obligations.md'
REQUIRED_THEOREM_HEADINGS = [
    '## T1: Completeness',
    '## T2: Knowledge Soundness',
    '## T3: Zero-Knowledge / HVZK \\(\\rightarrow\\) NIZK via Fiat-Shamir',
    '## T4: Simulation-Extractability Decision',
    '## T5: Commitment Binding',
]
REQUIRED_THEOREM_FIELDS = [
    '**Theorem ID**:',
    '**Assumption**:',
    '**Model**:',
    '**Statement sketch**:',
    '**Proof technique**:',
    '**Reduction target**:',
    '**Status**:',
]
SCORECARD_PATH = '.sisyphus/research/p1/scorecard.md'
DECISION_PATH = '.sisyphus/research/p1/RG-P1-decision.md'
REVIEW_PATH = '.sisyphus/reviews/p1-scorecard-review.md'

SUBCHECKS = ['prior-art', 'prior-art-matrix', 'novelty-gap', 'threat-model', 'theorem-inventory', 'scorecard', 'decision', 'scorecard-review']
REQUIRED_CANDIDATES = [
    'SLAP',
    'Greyhound',
    'Beullens one-shot lattice ZK',
    'SNARK-friendly hash-of-RLWE-witness',
    'LANES / LNS21',
    'Rust-in-zkVM (SP1 / RISC0 / Jolt)',
]
FALLBACK_REVIEW_ALIASES = {
    'Greyhound': ['Greyhound'],
    'Rust-in-zkVM (SP1 / RISC0 / Jolt)': ['Rust-in-zkVM', 'SP1', 'RISC0', 'Jolt'],
}
REQUIRED_WEIGHTED_COLUMNS = [
    ('Scale 20%', Decimal('0.20')),
    ('Verifier 25%', Decimal('0.25')),
    ('FHE compat 20%', Decimal('0.20')),
    ('Novelty cost 15%', Decimal('0.15')),
    ('PQ posture 10%', Decimal('0.10')),
    ('Feasibility 10%', Decimal('0.10')),
]
REVIEW_REQUIRED_FIELDS = [
    '## Summary',
    'VERDICT: APPROVE',
    '## Scoring Rationale',
    '## Primary Justification',
    '## Fallback Justification',
    '## Risks',
]


def check_artifacts() -> tuple[bool, list[str]]:
    details: list[str] = []
    ok = True
    for path in ARTIFACTS:
        if os.path.exists(path):
            details.append(f"[OK] {path}")
        else:
            details.append(f"[WARN] artifact not yet present (stub phase): {path}")
            # In stub phase, missing artifacts are warnings not failures
    return ok, details


def count_markdown_table_rows(path: str) -> int:
    with open(path, 'r', encoding='utf-8') as f:
        lines = [line.rstrip('\n') for line in f]

    in_table = False
    row_count = 0
    separator_seen = False
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith('|'):
            if in_table and separator_seen:
                break
            continue
        if not in_table:
            in_table = True
            continue
        if re.fullmatch(r"\|(?:\s*:?-{3,}:?\s*\|)+", stripped):
            separator_seen = True
            continue
        if separator_seen:
            row_count += 1
    return row_count


def extract_markdown_table(content: str, heading: str) -> tuple[list[str], list[list[str]]] | None:
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != heading:
            continue
        table_lines: list[str] = []
        j = i + 1
        while j < len(lines):
            stripped = lines[j].strip()
            if not stripped:
                if table_lines:
                    break
                j += 1
                continue
            if not stripped.startswith('|'):
                if table_lines:
                    break
                j += 1
                continue
            table_lines.append(stripped)
            j += 1
        if len(table_lines) < 2:
            return None
        header = [cell.strip() for cell in table_lines[0].strip('|').split('|')]
        rows: list[list[str]] = []
        for row in table_lines[2:]:
            rows.append([cell.strip() for cell in row.strip('|').split('|')])
        return header, rows
    return None


def parse_decimal(value: str) -> Decimal | None:
    try:
        return Decimal(value)
    except InvalidOperation:
        return None


def parse_scorecard_freeze(content: str) -> tuple[str | None, list[str]]:
    primary_match = re.search(r'Primary:\s*(.+)', content)
    fallback_matches = cast(list[str], re.findall(r'Fallback:\s*(.+)', content))

    def clean(raw: str) -> str:
        return raw.replace('**', '').strip()

    primary = clean(primary_match.group(1)) if primary_match else None
    fallbacks = [clean(match) for match in fallback_matches]
    return primary, fallbacks


def parse_scorecard_table(content: str) -> tuple[dict[str, dict[str, Decimal | int]], list[str]]:
    extracted = extract_markdown_table(content, '## Weighted Scores')
    if extracted is None:
        return {}, ['[FAIL] could not parse weighted scores table']

    header, rows = extracted
    expected_header = ['Candidate'] + [name for name, _ in REQUIRED_WEIGHTED_COLUMNS] + ['Weighted total', 'Rank']
    details: list[str] = []
    if header != expected_header:
        return {}, [f'[FAIL] weighted scores header must be {expected_header}; found {header}']

    parsed: dict[str, dict[str, Decimal | int]] = {}
    for row in rows:
        if len(row) != len(expected_header):
            return {}, [f'[FAIL] malformed scorecard row: {row}']
        candidate = row[0]
        candidate_data: dict[str, Decimal | int] = {}
        for idx, (column, _) in enumerate(REQUIRED_WEIGHTED_COLUMNS, start=1):
            value = parse_decimal(row[idx])
            if value is None:
                return {}, [f'[FAIL] candidate {candidate} has non-numeric value for {column}: {row[idx]}']
            candidate_data[column] = value
        total_value = parse_decimal(row[-2])
        rank_value = parse_decimal(row[-1])
        if total_value is None:
            return {}, [f'[FAIL] candidate {candidate} has non-numeric weighted total: {row[-2]}']
        if rank_value is None or rank_value != rank_value.to_integral_value():
            return {}, [f'[FAIL] candidate {candidate} has invalid rank: {row[-1]}']
        candidate_data['Weighted total'] = total_value
        candidate_data['Rank'] = int(rank_value)
        parsed[candidate] = candidate_data

    details.append('[OK] parsed weighted scores table')
    return parsed, details


def validate_scorecard_semantics(content: str) -> tuple[bool, list[str], str | None, list[str]]:
    details: list[str] = []
    ok = True

    score_rows, parse_details = parse_scorecard_table(content)
    details.extend(parse_details)
    if not score_rows:
        return False, details, None, []

    candidate_names = list(score_rows.keys())
    if set(candidate_names) != set(REQUIRED_CANDIDATES) or len(candidate_names) != len(REQUIRED_CANDIDATES):
        details.append(f'[FAIL] weighted scores candidates must be exactly {REQUIRED_CANDIDATES}; found {candidate_names}')
        ok = False
    else:
        details.append('[OK] weighted scores include all required candidates')

    for column, weight in REQUIRED_WEIGHTED_COLUMNS:
        details.append(f'[OK] validated scorecard column: {column} (weight {weight})')

    quant = Decimal('0.01')
    recomputed_totals: dict[str, Decimal] = {}
    for candidate, row in score_rows.items():
        recomputed_total = Decimal('0')
        for column, weight in REQUIRED_WEIGHTED_COLUMNS:
            recomputed_total += cast(Decimal, row[column]) * weight
        recomputed_total = recomputed_total.quantize(quant)
        recomputed_totals[candidate] = recomputed_total
        reported_total = cast(Decimal, row['Weighted total']).quantize(quant)
        if reported_total != recomputed_total:
            details.append(
                f'[FAIL] weighted total mismatch for {candidate}: reported {reported_total}, expected {recomputed_total}'
            )
            ok = False
        else:
            details.append(f'[OK] weighted total verified for {candidate}: {reported_total}')

    ranks = [cast(int, score_rows[candidate]['Rank']) for candidate in REQUIRED_CANDIDATES if candidate in score_rows]
    if sorted(ranks) != list(range(1, len(REQUIRED_CANDIDATES) + 1)):
        details.append(f'[FAIL] ranks must be a permutation of 1..{len(REQUIRED_CANDIDATES)}; found {ranks}')
        ok = False
    else:
        details.append('[OK] rank column is a complete permutation')

    sorted_candidates = sorted(
        score_rows.items(),
        key=lambda item: (-recomputed_totals[item[0]], cast(int, item[1]['Rank']), item[0]),
    )
    expected_rank_order = [candidate for candidate, _ in sorted_candidates]
    actual_rank_order = [candidate for candidate, _ in sorted(score_rows.items(), key=lambda item: cast(int, item[1]['Rank']))]
    if actual_rank_order != expected_rank_order:
        details.append(f'[FAIL] rank order {actual_rank_order} does not match weighted-total order {expected_rank_order}')
        ok = False
    else:
        details.append('[OK] rank order matches weighted totals')

    primary, fallbacks = parse_scorecard_freeze(content)
    if primary is None:
        details.append('[FAIL] missing scorecard primary freeze entry')
        ok = False
    else:
        details.append(f'[OK] parsed primary freeze: {primary}')
    if not fallbacks:
        details.append('[FAIL] missing scorecard fallback freeze entries')
        ok = False
    else:
        details.append(f'[OK] parsed fallback freezes: {fallbacks}')

    if primary is not None:
        top_ranked = actual_rank_order[0] if actual_rank_order else None
        if primary != top_ranked:
            details.append(f'[FAIL] primary freeze must match the top-ranked candidate; primary={primary}, top-ranked={top_ranked}')
            ok = False
        else:
            details.append(f'[OK] primary freeze matches top-ranked candidate: {primary}')

    return ok, details, primary, fallbacks


def parse_decision_freeze(content: str) -> tuple[str | None, list[str]]:
    primary_match = re.search(r'Primary frozen for P1:\*\*\s*([^\n]+)', content)
    if primary_match is None:
        primary_match = re.search(r'Primary frozen for P1:\s*([^\n]+)', content)
    fallback_matches = cast(list[str], re.findall(r'Fallback frozen for P1:\*\*\s*([^\n]+)', content))
    if not fallback_matches:
        fallback_matches = cast(list[str], re.findall(r'Fallback frozen for P1:\s*([^\n]+)', content))
    primary = primary_match.group(1).replace('**', '').strip() if primary_match else None
    fallbacks = [match.replace('**', '').strip() for match in fallback_matches]
    return primary, fallbacks


def check_prior_art_matrix() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: prior-art-matrix"]
    if not os.path.exists(PRIOR_ART_MATRIX):
        return False, details + [f"[FAIL] missing required artifact: {PRIOR_ART_MATRIX}"]

    row_count = count_markdown_table_rows(PRIOR_ART_MATRIX)
    details.append(f"[OK] found matrix artifact: {PRIOR_ART_MATRIX}")
    if row_count < 10:
        details.append(f"[FAIL] prior-art matrix must contain at least 10 data rows; found {row_count}")
        return False, details

    details.append(f"[OK] prior-art matrix rows: {row_count}")
    return True, details


def check_novelty_gap() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: novelty-gap"]
    memo_path = ".sisyphus/research/p1/novelty-memo.md"
    if not os.path.exists(memo_path):
        return False, details + [f"[FAIL] missing required artifact: {memo_path}"]
    
    with open(memo_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    required_headings = ["## Required Novelty", "## Aggressive Bets", "## Risk Register", "## Pivot Triggers"]
    ok = True
    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")
            
    if ok:
        details.append(f"[OK] {memo_path} meets requirements")
        
    return ok, details


def check_threat_model() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: threat-model"]
    if not os.path.exists(THREAT_MODEL_PATH):
        return False, details + [f"[FAIL] missing required artifact: {THREAT_MODEL_PATH}"]

    with open(THREAT_MODEL_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_sections = [
        "## Goal",
        "## Non-Goals",
        "## Required Theorems",
        "## Allowed Assumptions",
        "## Threat Model Matrix",
        "## Success Metrics",
        "## Downstream Outputs",
    ]
    required_markers = [
        "Adversary model",
        "Static corruption",
        "ROM",
        "QROM",
        "Simulation-soundness",
        "Knowledge soundness",
        "Extractor model",
        "Rewinding",
        "Straight-line",
        "P2",
        "P4",
        "q",
        "ring degree",
        "error bound",
    ]
    required_rows = [
        "| Adversary model |",
        "| Simulation-soundness |",
        "| Extractor model |",
    ]

    ok = True
    for section in required_sections:
        if section not in content:
            details.append(f"[FAIL] missing required section: {section}")
            ok = False
        else:
            details.append(f"[OK] found section: {section}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required threat-model marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found marker: {marker}")

    for row in required_rows:
        if row not in content:
            details.append(f"[FAIL] missing required threat-model row: {row}")
            ok = False
        else:
            details.append(f"[OK] found row: {row}")

    if ok:
        details.append(f"[OK] {THREAT_MODEL_PATH} meets requirements")

    return ok, details


def count_theorem_headings(path: str) -> int:
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    return len(re.findall(r'^##\s+T\d+\s*:', content, flags=re.MULTILINE))


def parse_inventory_theorem_ids(content: str) -> list[str]:
    return re.findall(r'\*\*Theorem ID\*\*:\s*(P1-T\d+)', content)


def parse_obligation_theorem_ids(content: str) -> list[str]:
    return re.findall(r'^\|\s*P1\s*\|\s*(P1-T\d+)\s*\|', content, flags=re.MULTILINE)


def check_theorem_inventory() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: theorem-inventory"]
    if not os.path.exists(THEOREM_INVENTORY_PATH):
        return False, details + [f"[FAIL] missing required artifact: {THEOREM_INVENTORY_PATH}"]
    if not os.path.exists(OBLIGATIONS_PATH):
        return False, details + [f"[FAIL] missing required artifact: {OBLIGATIONS_PATH}"]

    heading_count = count_theorem_headings(THEOREM_INVENTORY_PATH)
    details.append(f"[OK] found theorem inventory artifact: {THEOREM_INVENTORY_PATH}")
    if heading_count < 5:
        details.append(f"[FAIL] theorem inventory must contain at least 5 theorem headings; found {heading_count}")
        return False, details

    with open(THEOREM_INVENTORY_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    with open(OBLIGATIONS_PATH, 'r', encoding='utf-8') as f:
        obligations_content = f.read()

    ok = True
    for heading in REQUIRED_THEOREM_HEADINGS:
        if heading not in content:
            details.append(f"[FAIL] missing required theorem heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found theorem heading: {heading}")

    for field in REQUIRED_THEOREM_FIELDS:
        field_count = content.count(field)
        if field_count < 5:
            details.append(f"[FAIL] required field '{field}' must appear at least 5 times; found {field_count}")
            ok = False
        else:
            details.append(f"[OK] required field '{field}' occurrences: {field_count}")

    expected_ids = [f'P1-T{i}' for i in range(1, 6)]
    inventory_ids = parse_inventory_theorem_ids(content)
    obligation_ids = parse_obligation_theorem_ids(obligations_content)
    if inventory_ids != expected_ids:
        details.append(
            f"[FAIL] theorem inventory IDs must be exactly {expected_ids}; found {inventory_ids}"
        )
        ok = False
    else:
        details.append(f"[OK] theorem inventory IDs match expected sequence: {inventory_ids}")

    if obligation_ids != expected_ids:
        details.append(
            f"[FAIL] obligations P1 theorem IDs must be exactly {expected_ids}; found {obligation_ids}"
        )
        ok = False
    else:
        details.append(f"[OK] obligations P1 theorem IDs match expected sequence: {obligation_ids}")

    if inventory_ids != obligation_ids:
        details.append(
            f"[FAIL] theorem inventory IDs and obligations IDs differ: {inventory_ids} vs {obligation_ids}"
        )
        ok = False
    else:
        details.append("[OK] theorem inventory IDs align with obligations P1 rows")

    if not ok:
        return False, details

    details.append(f"[OK] theorem heading count: {heading_count}")
    return True, details


def check_scorecard() -> tuple[bool, list[str]]:
    details: list[str] = ["subcheck: scorecard"]
    if not os.path.exists(SCORECARD_PATH):
        return False, details + [f"[FAIL] missing required artifact: {SCORECARD_PATH}"]

    with open(SCORECARD_PATH, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headings = [
        "## Weighted Criteria",
        "## Weighted Scores",
        "## Freeze Decision",
    ]
    required_markers = [
        "Primary:",
        "Fallback:",
    ]

    ok = True
    for heading in required_headings:
        if heading not in content:
            details.append(f"[FAIL] missing required heading: {heading}")
            ok = False
        else:
            details.append(f"[OK] found heading: {heading}")

    for marker in required_markers:
        if marker not in content:
            details.append(f"[FAIL] missing required scorecard marker: {marker}")
            ok = False
        else:
            details.append(f"[OK] found marker: {marker}")

    semantic_ok, semantic_details, _, _ = validate_scorecard_semantics(content)
    details.extend(semantic_details)
    ok = ok and semantic_ok

    if ok:
        details.append(f"[OK] {SCORECARD_PATH} meets requirements")

    return ok, details


def check_decision() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: decision']
    if not os.path.exists(DECISION_PATH):
        return False, details + [f'[FAIL] missing required artifact: {DECISION_PATH}']
    if not os.path.exists(SCORECARD_PATH):
        return False, details + [f'[FAIL] missing required artifact: {SCORECARD_PATH}']

    with open(DECISION_PATH, 'r', encoding='utf-8') as f:
        decision_content = f.read()
    with open(SCORECARD_PATH, 'r', encoding='utf-8') as f:
        scorecard_content = f.read()

    required_sections = ['## Decision', '## Rationale', '## Sign-off']
    required_markers = ['Prometheus:', 'External Advisor:', '[PENDING HUMAN REVIEW]']
    ok = True
    for section in required_sections:
        if section not in decision_content:
            details.append(f'[FAIL] missing required decision section: {section}')
            ok = False
        else:
            details.append(f'[OK] found decision section: {section}')
    for marker in required_markers:
        if marker not in decision_content:
            details.append(f'[FAIL] missing required decision marker: {marker}')
            ok = False
        else:
            details.append(f'[OK] found decision marker: {marker}')

    _, scorecard_details, scorecard_primary, scorecard_fallbacks = validate_scorecard_semantics(scorecard_content)
    details.extend([f'[INFO] {detail}' for detail in scorecard_details if detail.startswith('[OK]')])
    decision_primary, decision_fallbacks = parse_decision_freeze(decision_content)
    if decision_primary is None:
        details.append('[FAIL] decision artifact must declare exactly one primary freeze')
        ok = False
    else:
        details.append(f'[OK] parsed decision primary: {decision_primary}')
    if not decision_fallbacks:
        details.append('[FAIL] decision artifact must declare at least one fallback freeze')
        ok = False
    else:
        details.append(f'[OK] parsed decision fallbacks: {decision_fallbacks}')

    if scorecard_primary is not None and decision_primary != scorecard_primary:
        details.append(f'[FAIL] primary mismatch between scorecard and decision: {scorecard_primary} vs {decision_primary}')
        ok = False
    else:
        details.append('[OK] decision primary matches scorecard primary')

    if scorecard_fallbacks and decision_fallbacks != scorecard_fallbacks:
        details.append(f'[FAIL] fallback mismatch between scorecard and decision: {scorecard_fallbacks} vs {decision_fallbacks}')
        ok = False
    else:
        details.append('[OK] decision fallbacks match scorecard fallbacks')

    if ok:
        details.append(f'[OK] {DECISION_PATH} meets requirements')
    return ok, details


def check_scorecard_review() -> tuple[bool, list[str]]:
    details: list[str] = ['subcheck: scorecard-review']
    if not os.path.exists(REVIEW_PATH):
        return False, details + [f'[FAIL] missing required artifact: {REVIEW_PATH}']
    if not os.path.exists(SCORECARD_PATH):
        return False, details + [f'[FAIL] missing required artifact: {SCORECARD_PATH}']

    with open(REVIEW_PATH, 'r', encoding='utf-8') as f:
        review_content = f.read()
    with open(SCORECARD_PATH, 'r', encoding='utf-8') as f:
        scorecard_content = f.read()

    ok = True
    for field in REVIEW_REQUIRED_FIELDS:
        if field not in review_content:
            details.append(f'[FAIL] missing required review field: {field}')
            ok = False
        else:
            details.append(f'[OK] found review field: {field}')

    _, _, scorecard_primary, scorecard_fallbacks = validate_scorecard_semantics(scorecard_content)
    if scorecard_primary is not None and scorecard_primary not in review_content:
        details.append(f'[FAIL] review memo must include primary reference: {scorecard_primary}')
        ok = False
    else:
        details.append('[OK] review memo references scorecard primary')
    for fallback in scorecard_fallbacks:
        aliases = FALLBACK_REVIEW_ALIASES.get(fallback, [fallback])
        if not any(alias in review_content for alias in aliases):
            details.append(f'[FAIL] review memo must include fallback reference: {fallback}')
            ok = False
        else:
            details.append(f'[OK] review memo references fallback: {fallback}')

    if ok:
        details.append(f'[OK] {REVIEW_PATH} meets requirements')
    return ok, details

def make_subcheck(name: str) -> Callable[[], tuple[bool, list[str]]]:
    def fn() -> tuple[bool, list[str]]:
        ok, details = check_artifacts()
        details.insert(0, f"subcheck: {name}")
        return ok, details
    fn.__name__ = name
    return fn


def main():
    parser = argparse.ArgumentParser(description=f"{GATE_NAME} gate")
    _ = parser.add_argument("--check", default=None, choices=SUBCHECKS)
    _ = parser.add_argument("--stub", action="store_true", help="Always PASS (stub mode)")
    args = parser.parse_args()

    subchecks_map: dict[str, Callable[[], tuple[bool, list[str]]]] = {
        name: make_subcheck(name) for name in SUBCHECKS
    }
    subchecks_map['prior-art'] = check_prior_art_matrix
    subchecks_map['prior-art-matrix'] = check_prior_art_matrix
    subchecks_map['novelty-gap'] = check_novelty_gap
    subchecks_map['threat-model'] = check_threat_model
    subchecks_map['theorem-inventory'] = check_theorem_inventory
    subchecks_map['scorecard'] = check_scorecard
    subchecks_map['decision'] = check_decision
    subchecks_map['scorecard-review'] = check_scorecard_review
    run_gate(GATE_NAME, subchecks_map, args)


if __name__ == "__main__":
    main()
