"""Tests for .sisyphus/scripts validators."""
import os
import subprocess
import sys
import tempfile
import textwrap

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..")


def run_script(script_name: str, *args: str) -> tuple[int, str, str]:
    script = os.path.join(SCRIPTS_DIR, script_name)
    result = subprocess.run(
        [sys.executable, script] + list(args),
        capture_output=True, text=True
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# validate-obligations-schema.py
# ---------------------------------------------------------------------------

OBLIGATIONS_VALID = textwrap.dedent("""\
    # Proof Obligations Registry

    | Problem | Theorem-ID | Informal Statement | Status | Proof File Path | Paper Section |
    |---------|------------|--------------------|--------|-----------------|---------------|
    | P1 | T1.1 | Soundness of NIZK | Open | docs/security-proofs/p1.md | §3 |
""")

OBLIGATIONS_MISSING_FIELD = textwrap.dedent("""\
    # Proof Obligations Registry

    | Problem | Theorem-ID | Informal Statement | Status |
    |---------|------------|--------------------|----|
    | P1 | T1.1 | Soundness | Open |
""")

OBLIGATIONS_MALFORMED = "not a table at all\njust random text\n"

OBLIGATIONS_P4_FILTERABLE = textwrap.dedent("""\
    # Proof Obligations Registry

    | Problem | Theorem-ID | Informal Statement | Status | Proof File Path | Paper Section |
    |---------|------------|--------------------|--------|-----------------|---------------|
    | P4 | P4-T1 | Correctness | proven | docs/security-proofs/p4/t1.md | §P4-Correctness |
    | P4 | P4-T2 | Secrecy | proven | docs/security-proofs/p4/t2.md | §P4-Secrecy |
    | P1 | P1-T1 | Other theorem | skeleton | docs/security-proofs/p1/t1.md | §P1-Soundness |
""")

OBLIGATIONS_P4_FILTER_MISMATCH = textwrap.dedent("""\
    # Proof Obligations Registry

    | Problem | Theorem-ID | Informal Statement | Status | Proof File Path | Paper Section |
    |---------|------------|--------------------|--------|-----------------|---------------|
    | P4 | P4-T1 | Correctness | proven | docs/security-proofs/p4/t1.md | §P4-Correctness |
    | P4 | P4-T2 | Secrecy | skeleton | docs/security-proofs/p4/t2.md | §P4-Secrecy |
""")


def test_validate_obligations_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(OBLIGATIONS_VALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-obligations-schema.py", "--path", path)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_obligations_missing_field():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(OBLIGATIONS_MISSING_FIELD)
        path = f.name
    try:
        rc, out, _ = run_script("validate-obligations-schema.py", "--path", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_obligations_malformed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(OBLIGATIONS_MALFORMED)
        path = f.name
    try:
        rc, out, _ = run_script("validate-obligations-schema.py", "--path", path)
        # No table means no rows, but no columns either — should report missing columns
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_obligations_positional_path_and_filters():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(OBLIGATIONS_P4_FILTERABLE)
        path = f.name
    try:
        rc, out, _ = run_script(
            "validate-obligations-schema.py", path, "--problem", "P4", "--status", "proven"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS:" in out, f"Expected PASS output. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_obligations_filtered_status_mismatch():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(OBLIGATIONS_P4_FILTER_MISMATCH)
        path = f.name
    try:
        rc, out, _ = run_script(
            "validate-obligations-schema.py", path, "--problem", "P4", "--status", "proven"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "FAIL:" in out, f"Expected FAIL output. Output: {out}"
    finally:
        _ = os.unlink(path)


# ---------------------------------------------------------------------------
# validate-reviewer-memo.py
# ---------------------------------------------------------------------------

MEMO_VALID = textwrap.dedent("""\
    # External Reviewer Memo
    **Reviewer**: Test Reviewer
    **Date**: 2026-05-01

    ## Findings
    1. Everything looks good.

    ## Verdict
    VERDICT: APPROVE

    ---
    **Signature**: Test Reviewer
""")

MEMO_MISSING_VERDICT = textwrap.dedent("""\
    # External Reviewer Memo

    ## Findings
    1. Something.

    ## Verdict
    I think it is fine.
""")

MEMO_MALFORMED = "no sections, no verdict, just random text"


def test_validate_reviewer_memo_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(MEMO_VALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-reviewer-memo.py", "--memo", path)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_reviewer_memo_missing_verdict():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(MEMO_MISSING_VERDICT)
        path = f.name
    try:
        rc, out, _ = run_script("validate-reviewer-memo.py", "--memo", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_reviewer_memo_malformed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(MEMO_MALFORMED)
        path = f.name
    try:
        rc, out, _ = run_script("validate-reviewer-memo.py", "--memo", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


# ---------------------------------------------------------------------------
# validate-proof-skeletons.py
# ---------------------------------------------------------------------------

SKELETON_VALID = textwrap.dedent("""\
    # P1 Soundness Theorem

    ## Theorem
    The NIZK construction is sound under RLWE.

    ## Proof
    ### Status

    Status: Open

    ### Proof Technique

    Reduction to RLWE problem...

    ### Reduction Target

    RLWE

    ### Unresolved Lemmas

    - Unresolved Lemma 1: Extraction bound.

    ### Open Questions

    - Can the reduction be tightened?
""")

SKELETON_MISSING_PROOF = textwrap.dedent("""\
    # P1 Soundness Theorem

    ## Theorem
    The NIZK construction is sound under RLWE.

    Status: Open
""")

SKELETON_MALFORMED = "just some random text with no structure"

SKELETON_TWO_THEOREMS = textwrap.dedent("""\
    # P4 Combined Skeletons

    ## Theorem
    Theorem one.

    ## Proof
    ### Status

    Status: Skeleton

    ### Proof Technique

    Skeleton one.

    ### Reduction Target

    Assumption one.

    ### Unresolved Lemmas

    - Unresolved Lemma 1: First gap.

    ### Open Questions

    - First question.

    ## Theorem
    Theorem two.

    ## Proof
    ### Status

    Status: Skeleton

    ### Proof Technique

    Skeleton two.

    ### Reduction Target

    Assumption two.

    ### Unresolved Lemmas

    - Unresolved Lemma 1: Second gap.

    ### Open Questions

    - Second question.
""")

SKELETON_MISSING_OPEN_QUESTIONS = textwrap.dedent("""\
    # P1 Soundness Theorem

    ## Theorem
    The NIZK construction is sound under RLWE.

    ## Proof
    ### Status

    Status: Open

    ### Proof Technique

    Reduction to RLWE problem...

    ### Reduction Target

    RLWE

    ### Unresolved Lemmas

    - Unresolved Lemma 1: Extraction bound.
""")

NON_SKELETON_GUIDE = textwrap.dedent("""\
    # Security Proofs Guidelines

    This is a guide file, not a theorem skeleton.
""")


def test_validate_proof_skeletons_valid():
    with tempfile.TemporaryDirectory() as tmpdir:
        skeleton_dir = os.path.join(tmpdir, "p1")
        os.mkdir(skeleton_dir)
        fpath = os.path.join(skeleton_dir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_VALID)
        rc, out, _ = run_script("validate-proof-skeletons.py", "--dir", tmpdir)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"


def test_validate_proof_skeletons_missing_field():
    with tempfile.TemporaryDirectory() as tmpdir:
        skeleton_dir = os.path.join(tmpdir, "p1")
        os.mkdir(skeleton_dir)
        fpath = os.path.join(skeleton_dir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_MISSING_PROOF)
        rc, out, _ = run_script("validate-proof-skeletons.py", "--dir", tmpdir)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"


def test_validate_proof_skeletons_malformed():
    with tempfile.TemporaryDirectory() as tmpdir:
        skeleton_dir = os.path.join(tmpdir, "p1")
        os.mkdir(skeleton_dir)
        fpath = os.path.join(skeleton_dir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_MALFORMED)
        rc, out, _ = run_script("validate-proof-skeletons.py", "--dir", tmpdir)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"


def test_validate_proof_skeletons_positional_dir_and_min_thms():
    with tempfile.TemporaryDirectory() as tmpdir:
        skeleton_dir = os.path.join(tmpdir, "p4")
        os.mkdir(skeleton_dir)
        fpath = os.path.join(skeleton_dir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_TWO_THEOREMS)
        rc, out, err = run_script(
            "validate-proof-skeletons.py", tmpdir, "--min-thms", "2"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out} Err: {err}"


def test_validate_proof_skeletons_fails_when_too_few_theorems():
    with tempfile.TemporaryDirectory() as tmpdir:
        skeleton_dir = os.path.join(tmpdir, "p4")
        os.mkdir(skeleton_dir)
        fpath = os.path.join(skeleton_dir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_VALID)
        rc, out, _ = run_script(
            "validate-proof-skeletons.py", tmpdir, "--min-thms", "2"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"


def test_validate_proof_skeletons_missing_documented_section():
    with tempfile.TemporaryDirectory() as tmpdir:
        skeleton_dir = os.path.join(tmpdir, "p1")
        os.mkdir(skeleton_dir)
        fpath = os.path.join(skeleton_dir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_MISSING_OPEN_QUESTIONS)
        rc, out, _ = run_script("validate-proof-skeletons.py", "--dir", tmpdir)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "Open Questions" in out, f"Expected missing section report. Output: {out}"


def test_validate_proof_skeletons_default_ignores_non_skeleton_markdown():
    with tempfile.TemporaryDirectory() as tmpdir:
        proofs_dir = os.path.join(tmpdir, "p4")
        os.mkdir(proofs_dir)
        with open(os.path.join(proofs_dir, "t1.md"), "w") as f:
            _ = f.write(SKELETON_VALID)
        with open(os.path.join(tmpdir, "README.md"), "w") as f:
            _ = f.write(NON_SKELETON_GUIDE)
        with open(os.path.join(tmpdir, "obligations.md"), "w") as f:
            _ = f.write(OBLIGATIONS_VALID)
        rc, out, _ = run_script("validate-proof-skeletons.py", "--dir", tmpdir)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"


def test_validate_proof_skeletons_direct_skeleton_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        fpath = os.path.join(tmpdir, "t1.md")
        with open(fpath, "w") as f:
            _ = f.write(SKELETON_VALID)
        rc, out, _ = run_script("validate-proof-skeletons.py", "--dir", tmpdir)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS:" in out, f"Expected validator to inspect direct skeleton dir. Output: {out}"


# ---------------------------------------------------------------------------
# validate-bundle.py
# ---------------------------------------------------------------------------

BUNDLE_VALID = textwrap.dedent("""\
    # Downstream Contract Bundle

    ## Problem Statement
    Build a threshold FHE scheme.

    ## Acceptance Criteria
    - Proof passes
    - Benchmarks within budget

    ## Deliverables
    - Implemented crate
    - Tests green
""")

BUNDLE_MISSING_FIELD = textwrap.dedent("""\
    # Downstream Contract Bundle

    ## Problem Statement
    Build a threshold FHE scheme.
""")

BUNDLE_MALFORMED = "x" * 10


def test_validate_bundle_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(BUNDLE_VALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-bundle.py", "--bundle", path)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_bundle_missing_field():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(BUNDLE_MISSING_FIELD)
        path = f.name
    try:
        rc, out, _ = run_script("validate-bundle.py", "--bundle", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_bundle_malformed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(BUNDLE_MALFORMED)
        path = f.name
    try:
        rc, out, _ = run_script("validate-bundle.py", "--bundle", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


# ---------------------------------------------------------------------------
# validate-prior-art.py
# ---------------------------------------------------------------------------

BIB_VALID = textwrap.dedent("""\
    @article{foo2023,
      author = {Foo, Bar},
      title = {A Study},
      year = {2023},
    }
    @inproceedings{baz2022,
      author = {Baz},
      title = {Other Work},
      year = {2022},
    }
""")

BIB_EMPTY = ""

BIB_MALFORMED = "this is not a bib file at all !!! @@@"


def test_validate_prior_art_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bib", delete=False) as f:
        _ = f.write(BIB_VALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-prior-art.py", "--bib", path)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_prior_art_missing_field():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bib", delete=False) as f:
        _ = f.write(BIB_EMPTY)
        path = f.name
    try:
        rc, out, _ = run_script("validate-prior-art.py", "--bib", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_prior_art_malformed():
    # A bib file with no valid entries should fail
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bib", delete=False) as f:
        _ = f.write(BIB_MALFORMED)
        path = f.name
    try:
        rc, out, _ = run_script("validate-prior-art.py", "--bib", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


# ---------------------------------------------------------------------------
# validate-pins.py
# ---------------------------------------------------------------------------

TEX_VALID = textwrap.dedent("""\
    \\documentclass{article}
    \\begin{document}
    As shown in \\cite{foo2023}, see also \\ref{sec:proof}.
    \\end{document}
""")

TEX_MISSING_CITE = textwrap.dedent("""\
    \\documentclass{article}
    \\begin{document}
    No references here.
    \\end{document}
""")

TEX_MALFORMED = ""
MD_PINS_VALID = textwrap.dedent("""\
    # Reproducing

    ## P4
    - `serde = "1.0.228"`
    - `serde_json = "1.0.145"`
    - `sha2 = "0.10.9"`
    - `sha3 = "0.10.8"`
""")

MD_PINS_INVALID = textwrap.dedent("""\
    # Reproducing

    ## P4
    - serde 1.0
    - sha2 latest
""")


def test_validate_pins_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tex", delete=False) as f:
        _ = f.write(TEX_VALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-pins.py", "--paper", path)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_pins_missing_field():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tex", delete=False) as f:
        _ = f.write(TEX_MISSING_CITE)
        path = f.name
    try:
        rc, out, _ = run_script("validate-pins.py", "--paper", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_pins_malformed():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tex", delete=False) as f:
        _ = f.write(TEX_MALFORMED)
        path = f.name
    try:
        rc, out, _ = run_script("validate-pins.py", "--paper", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_pins_markdown_positional_valid():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(MD_PINS_VALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-pins.py", path)
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_pins_markdown_missing_pin_entries():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(MD_PINS_INVALID)
        path = f.name
    try:
        rc, out, _ = run_script("validate-pins.py", path)
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
    finally:
        _ = os.unlink(path)
