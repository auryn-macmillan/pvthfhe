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


def run_script_in_cwd(script_name: str, cwd: str, *args: str) -> tuple[int, str, str]:
    script = os.path.join(SCRIPTS_DIR, script_name)
    result = subprocess.run(
        [sys.executable, script] + list(args),
        capture_output=True,
        text=True,
        cwd=cwd,
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
    # P4 to P1 Bundle

    ## Assumptions
    - honest majority

    ## Public Key Format
    - bfv bytes

    ## Share Format
    - shamir share

    ## Parameter Schema
    - p = 2^61 - 1

    ## Transcript Schema
    - artifact shape

    ## Encoding Commitments
    - sha256(session_id || id || secret_value)

    ## Unresolved Risks
    - rlwe upgrade pending
""")

BUNDLE_MISSING_FIELD = textwrap.dedent("""\
    # P4 to P1 Bundle

    ## Assumptions
    - honest majority
""")

BUNDLE_MALFORMED = "x" * 10

BUNDLE_P4_VALID = textwrap.dedent("""\
    # P4 to P1 Bundle

    ## Assumptions
    - honest majority

    ## Public Key Format
    - bfv bytes

    ## Share Format
    - shamir share

    ## Parameter Schema
    - p = 2^61 - 1

    ## Transcript Schema
    - artifact shape

    ## Encoding Commitments
    - sha256(session_id || id || secret_value)

    ## Unresolved Risks
    - rlwe upgrade pending
""")

BUNDLE_P4_MISSING_SECTION = textwrap.dedent("""\
    # P4 to P1 Bundle

    ## Assumptions
    - honest majority

    ## Public Key Format
    - bfv bytes

    ## Share Format
    - shamir share

    ## Transcript Schema
    - artifact shape

    ## Encoding Commitments
    - sha256(session_id || id || secret_value)

    ## Unresolved Risks
    - rlwe upgrade pending
""")


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


def test_validate_bundle_positional_path_and_p4_required_fields():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(BUNDLE_P4_VALID)
        path = f.name
    try:
        rc, out, _ = run_script(
            "validate-bundle.py",
            path,
            "--required-fields",
            "## Assumptions",
            "## Public Key Format",
            "## Share Format",
            "## Parameter Schema",
            "## Transcript Schema",
            "## Encoding Commitments",
            "## Unresolved Risks",
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS:" in out, f"Expected PASS output. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_validate_bundle_p4_missing_required_section_fails():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        _ = f.write(BUNDLE_P4_MISSING_SECTION)
        path = f.name
    try:
        rc, out, _ = run_script(
            "validate-bundle.py",
            path,
            "--required-fields",
            "## Assumptions",
            "## Public Key Format",
            "## Share Format",
            "## Parameter Schema",
            "## Transcript Schema",
            "## Encoding Commitments",
            "## Unresolved Risks",
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "## Parameter Schema" in out, f"Expected missing section report. Output: {out}"
    finally:
        _ = os.unlink(path)


def test_p4_impl_gate_impl_green_requires_reviewer_memo_and_frozen_claims():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = os.path.join(tmpdir, "repo")
        os.makedirs(os.path.join(root, ".sisyphus", "scripts", "tests"), exist_ok=True)
        os.makedirs(os.path.join(root, ".sisyphus", "contracts"), exist_ok=True)
        os.makedirs(os.path.join(root, ".sisyphus", "reviews"), exist_ok=True)
        os.makedirs(os.path.join(root, "paper"), exist_ok=True)
        os.makedirs(os.path.join(root, "crates", "pvthfhe-aggregator", "src", "keygen"), exist_ok=True)

        for script_name in [
            "_gate_utils.py",
            "validate-bundle.py",
            "validate-reviewer-memo.py",
            "p4-impl-gate.py",
        ]:
            source = os.path.join(SCRIPTS_DIR, script_name)
            target = os.path.join(root, ".sisyphus", "scripts", script_name)
            with open(source, "r", encoding="utf-8") as src, open(target, "w", encoding="utf-8") as dst:
                _ = dst.write(src.read())

        bundle_path = os.path.join(root, ".sisyphus", "contracts", "p4-to-p1-bundle.md")
        with open(bundle_path, "w", encoding="utf-8") as f:
            _ = f.write(BUNDLE_VALID)

        memo_path = os.path.join(root, ".sisyphus", "reviews", "p4-impl-gate-review.md")
        with open(memo_path, "w", encoding="utf-8") as f:
            _ = f.write(MEMO_VALID)

        claims_path = os.path.join(root, "paper", "claims-table.md")
        with open(claims_path, "w", encoding="utf-8") as f:
            _ = f.write(
                (
                    "| Problem | Theorem Label | Informal Claim | Status | Paper Section | Proof File |\n"
                    "|---------|---------------|----------------|--------|---------------|------------|\n"
                    "| P4 | T-P4.1 | claim | measured, frozen | Section 4 | proof |\n"
                )
            )

        artifact_path = os.path.join(root, "crates", "pvthfhe-aggregator", "src", "keygen", "protocol.rs")
        with open(artifact_path, "w", encoding="utf-8") as f:
            _ = f.write("// artifact present\n")

        rc, out, err = run_script_in_cwd("p4-impl-gate.py", root, "--check", "impl-green")
        assert rc == 0, f"Expected 0, got {rc}. Output: {out} Err: {err}"
        assert "reviewer memo validated" in out, f"Expected reviewer memo validation output. Output: {out}"
        assert "claims table shows frozen P4 row" in out, f"Expected frozen-claims output. Output: {out}"


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


# ---------------------------------------------------------------------------
# p1-research-gate.py
# ---------------------------------------------------------------------------


def test_p1_research_gate_accepts_prior_art_matrix_alias_and_checks_matrix_shape():
    with tempfile.TemporaryDirectory() as tmpdir:
        research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p1")
        os.makedirs(research_dir)
        matrix_path = os.path.join(research_dir, "prior-art.md")
        with open(matrix_path, "w", encoding="utf-8") as f:
            _ = f.write(
                (
                    "# Prior Art\n\n"
                    "| Scheme | Assumption | Prover time | Proof size | Verifier time | ROM/QROM | Post-quantum | Recursion-friendly | On-chain feasibility | License |\n"
                    "|---|---|---|---|---|---|---|---|---|---|\n"
                )
                + "\n".join(
                    [
                        f"| Scheme {i} | M-SIS | est | est | est | ROM | yes | maybe | no | unknown |"
                        for i in range(10)
                    ]
                )
                + "\n"
            )
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "prior-art-matrix"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-research-gate/prior-art-matrix" in out, out


def test_p1_research_gate_prior_art_matrix_fails_when_too_few_rows():
    with tempfile.TemporaryDirectory() as tmpdir:
        research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p1")
        os.makedirs(research_dir)
        matrix_path = os.path.join(research_dir, "prior-art.md")
        with open(matrix_path, "w", encoding="utf-8") as f:
            _ = f.write(
                (
                    "# Prior Art\n\n"
                    "| Scheme | Assumption | Prover time | Proof size | Verifier time | ROM/QROM | Post-quantum | Recursion-friendly | On-chain feasibility | License |\n"
                    "|---|---|---|---|---|---|---|---|---|---|\n"
                )
                + "\n".join(
                    [
                        f"| Scheme {i} | M-SIS | est | est | est | ROM | yes | maybe | no | unknown |"
                        for i in range(9)
                    ]
                )
                + "\n"
            )
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "prior-art-matrix"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "at least 10" in out, out


THREAT_MODEL_VALID = textwrap.dedent("""\
    # P1 Threat Model: Decrypt-Share NIZK

    ## Goal
    Fix the adversary and assumption model for P1.

    ## Non-Goals
    - Adaptive corruption is not a baseline claim.

    ## Required Theorems
    - Soundness / knowledge soundness for malformed decrypt-share proofs.
    - Sequential composition with P4 and P2.

    ## Allowed Assumptions
    - Adversary model: static malicious PPT adversary corrupting at most t-1 participants.
    - Network / scheduling: synchronous rounds with rushing adversary inside each round.
    - Random oracle model: ROM is the baseline model; QROM is deferred.
    - Extractor model: rewinding extractor for baseline knowledge soundness; Straight-line extraction is not claimed.

    ## Threat Model Matrix
    | Dimension | Baseline | Why it is fixed |
    | --- | --- | --- |
    | Adversary model | Malicious parties up to t-1 with verifier-observer access | Matches P4 honest-majority interface |
    | Corruption timing | Static corruption baseline; adaptive corruption out of scope | Matches frozen P4 bundle |
    | Soundness flavor | Knowledge soundness is required | P2 folding needs extractable accepted base proofs |
    | Simulation-soundness | Not required for the baseline sequential composition claim | P2 folds prover-generated P1 proofs and does not rely on simulated accepting P1 transcripts |
    | Extractor model | Rewinding extractor | Fiat-Shamir lattice PoK candidates usually provide rewinding-based extraction |
    | FHE parameter exposure | Public statement binds q, ring degree, and error bound | Prevents witness drift across folding and verification |

    ## Success Metrics
    - Threat-model rows freeze the adversary, oracle, and extractor choices.

    ## Downstream Outputs
    - P2 consumes the knowledge-sound P1 statement with fixed public parameters.
    - P4 sequential composition reuses the same static corruption interface.
""")


THREAT_MODEL_MISSING_SIM_SOUNDNESS = textwrap.dedent("""\
    # P1 Threat Model: Decrypt-Share NIZK

    ## Goal
    Fix the adversary and assumption model for P1.

    ## Allowed Assumptions
    - Adversary model: static malicious PPT adversary corrupting at most t-1 participants.
    - Extractor model: rewinding extractor for baseline knowledge soundness.

    ## Threat Model Matrix
    | Dimension | Baseline | Why it is fixed |
    | --- | --- | --- |
    | Adversary model | Malicious parties up to t-1 | Matches P4 |
    | Extractor model | Rewinding extractor | Baseline PoK |
""")


def test_p1_research_gate_threat_model_requires_expected_fields():
    with tempfile.TemporaryDirectory() as tmpdir:
        research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p1")
        os.makedirs(research_dir)
        threat_model_path = os.path.join(research_dir, "threat-model.md")
        with open(threat_model_path, "w", encoding="utf-8") as f:
            _ = f.write(THREAT_MODEL_VALID)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "threat-model"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-research-gate/threat-model" in out, out


def test_p1_research_gate_threat_model_fails_without_sim_soundness_row():
    with tempfile.TemporaryDirectory() as tmpdir:
        research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p1")
        os.makedirs(research_dir)
        threat_model_path = os.path.join(research_dir, "threat-model.md")
        with open(threat_model_path, "w", encoding="utf-8") as f:
            _ = f.write(THREAT_MODEL_MISSING_SIM_SOUNDNESS)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "threat-model"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "Simulation-soundness" in out, out


# ---------------------------------------------------------------------------
# p2-research-gate.py
# ---------------------------------------------------------------------------

P2_THREAT_MODEL_VALID = textwrap.dedent("""\
    # P2 Folding Threat Model

    ## 1. Corruption Model

    - Static malicious adversary corrupting at most t-1 of n parties.

    ## 2. Folding-Specific Threats

    - Invalid inner P1 proof injection.

    ## 3. Knowledge-Soundness Model

    - Rewinding extractor over the fold tree.

    ## 4. P1 Consistency Check

    - Corruption model matches P1.
""")


P2_THREAT_MODEL_MISSING_SECTION = textwrap.dedent("""\
    # P2 Folding Threat Model

    ## 1. Corruption Model

    - Static malicious adversary corrupting at most t-1 of n parties.

    ## 2. Folding-Specific Threats

    - Invalid inner P1 proof injection.
""")


def test_p2_research_gate_threat_model_requires_expected_sections():
    with tempfile.TemporaryDirectory() as tmpdir:
        research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p2")
        os.makedirs(research_dir)
        threat_model_path = os.path.join(research_dir, "threat-model.md")
        with open(threat_model_path, "w", encoding="utf-8") as f:
            _ = f.write(P2_THREAT_MODEL_VALID)
        rc, out, _ = run_script_in_cwd(
            "p2-research-gate.py", tmpdir, "--check", "threat-model"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p2-research-gate/threat-model" in out, out


def test_p2_research_gate_threat_model_fails_without_required_sections():
    with tempfile.TemporaryDirectory() as tmpdir:
        research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p2")
        os.makedirs(research_dir)
        threat_model_path = os.path.join(research_dir, "threat-model.md")
        with open(threat_model_path, "w", encoding="utf-8") as f:
            _ = f.write(P2_THREAT_MODEL_MISSING_SECTION)
        rc, out, _ = run_script_in_cwd(
            "p2-research-gate.py", tmpdir, "--check", "threat-model"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "Knowledge-Soundness" in out, out


P2_SCORECARD_VALID = textwrap.dedent("""\
    # P2 Candidate Scorecard

    ## Weighted Criteria

    | Criterion | Weight |
    | --- | --- |
    | RLWE-native | 25% |
    | Folding depth scalability | 20% |
    | Prover memory per fold step | 15% |
    | On-chain verifier cost (P3) | 20% |
    | Maturity/auditability | 10% |
    | Implementation deliverability | 10% |

    ## Weighted Scores

    | Candidate | RLWE-native 25% | Folding depth scalability 20% | Prover memory per fold step 15% | On-chain verifier cost (P3) 20% | Maturity/auditability 10% | Implementation deliverability 10% | Weighted total | Rank |
    | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
    | LatticeFold+ | 5 | 4 | 3 | 2 | 2 | 3 | 3.40 | 1 |
    | MicroNova | 1 | 3 | 3 | 5 | 4 | 4 | 3.10 | 2 |
    | Rust-in-zkVM | 1 | 4 | 2 | 4 | 4 | 5 | 3.05 | 3 |

    ## Freeze Decision

    Primary: LatticeFold+
    Fallback: MicroNova
""")


P2_DECISION_VALID = textwrap.dedent("""\
    # RG-P2 Decision Memo

    ## Primary: LatticeFold+

    Best native fit for the frozen P1 verifier relation because it keeps the fold relation inside a lattice-native commitment world. It is also the only surveyed candidate that directly optimizes the verifier and proof shape for lattice folding rather than wrapping the relation in a non-lattice accumulator. Its novelty risk is real, so the decision is only acceptable with an explicit delivery fallback.

    ## Fallback: MicroNova

    Delivery fallback when the native lattice path fails to satisfy the P2-T5 on-chain budget or cannot absorb the frozen SHA-256 and range-check obligations without unacceptable prover cost.

    ## Kill Criteria

    - Abandon the primary if the folded verifier cannot plausibly target <=14 KB proof size and <=5M gas after wrapping.

    ## Advisor Sign-off
    VERDICT: APPROVE
""")


def write_p2_gate_fixture_files(
    tmpdir: str,
    scorecard: str = P2_SCORECARD_VALID,
    decision: str = P2_DECISION_VALID,
) -> None:
    research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p2")
    os.makedirs(research_dir, exist_ok=True)
    with open(os.path.join(research_dir, "scorecard.md"), "w", encoding="utf-8") as f:
        _ = f.write(scorecard)
    with open(os.path.join(research_dir, "RG-P2-decision.md"), "w", encoding="utf-8") as f:
        _ = f.write(decision)


def test_p2_research_gate_scorecard_requires_candidates_primary_and_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p2_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p2-research-gate.py", tmpdir, "--check", "scorecard"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p2-research-gate/scorecard" in out, out


def test_p2_research_gate_scorecard_fails_without_fallback():
    bad_scorecard = P2_SCORECARD_VALID.replace("Fallback: MicroNova\n", "")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p2_gate_fixture_files(tmpdir, scorecard=bad_scorecard)
        rc, out, _ = run_script_in_cwd(
            "p2-research-gate.py", tmpdir, "--check", "scorecard"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "Fallback" in out, out


def test_p2_research_gate_rg_p2_requires_approve_verdict():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p2_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p2-research-gate.py", tmpdir, "--check", "rg-p2"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p2-research-gate/rg-p2" in out, out


def test_p2_research_gate_rg_p2_fails_without_approve_verdict():
    bad_decision = P2_DECISION_VALID.replace("VERDICT: APPROVE", "VERDICT: REJECT")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p2_gate_fixture_files(tmpdir, decision=bad_decision)
        rc, out, _ = run_script_in_cwd(
            "p2-research-gate.py", tmpdir, "--check", "rg-p2"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "VERDICT: APPROVE" in out, out


P1_SCORECARD_VALID = textwrap.dedent("""\
    # P1 Candidate Scorecard

    ## Weighted Criteria

    - Scale at n=1024 (20%)
    - Verifier cost for downstream P2 folding consumption (25%)
    - FHE-parameter compatibility (20%)
    - Novelty cost (15%)
    - PQ posture (10%)
    - Implementation feasibility / zkVM fallback viability (10%)

    ## Weighted Scores

    | Candidate | Scale 20% | Verifier 25% | FHE compat 20% | Novelty cost 15% | PQ posture 10% | Feasibility 10% | Weighted total | Rank |
    | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
    | SLAP | 4.00 | 3.75 | 4.50 | 3.25 | 4.50 | 3.00 | 3.88 | 1 |
    | Greyhound | 3.50 | 4.75 | 4.00 | 2.50 | 4.50 | 2.50 | 3.76 | 2 |
    | LANES / LNS21 | 3.50 | 2.75 | 4.50 | 4.00 | 4.50 | 3.25 | 3.66 | 3 |
    | Beullens one-shot lattice ZK | 3.75 | 3.50 | 4.00 | 3.25 | 4.50 | 2.75 | 3.64 | 4 |
    | SNARK-friendly hash-of-RLWE-witness | 2.50 | 5.00 | 3.25 | 3.75 | 2.00 | 4.00 | 3.56 | 5 |
    | Rust-in-zkVM (SP1 / RISC0 / Jolt) | 2.00 | 4.25 | 3.25 | 4.50 | 2.00 | 5.00 | 3.49 | 6 |

    ## Freeze Decision

    - **Primary: SLAP**
    - **Fallback: Greyhound**
    - **Fallback: Rust-in-zkVM (SP1 / RISC0 / Jolt)**
""")


P1_DECISION_VALID = textwrap.dedent("""\
    # RG-P1 Decision Record

    ## Decision

    - **Primary frozen for P1:** SLAP
    - **Fallback frozen for P1:** Greyhound
    - **Fallback frozen for P1:** Rust-in-zkVM (SP1 / RISC0 / Jolt)

    ## Rationale

    ROM baseline with rewinding extraction. QROM deferred.

    ## Sign-off

    **Prometheus:** APPROVE
    **External Advisor:** [PENDING HUMAN REVIEW]
""")


P1_REVIEW_VALID = textwrap.dedent("""\
    # P1 Scorecard Review Memo

    ## Summary

    VERDICT: APPROVE

    ## Scoring Rationale

    - Uses the weighted criteria and all required candidates.

    ## Primary Justification

    - SLAP is the top-ranked candidate.

    ## Fallback Justification

    - Greyhound and Rust-in-zkVM remain the named fallbacks.

    ## Risks

    - ROM baseline only; QROM is deferred.
""")


def write_p1_gate_fixture_files(tmpdir: str, scorecard: str = P1_SCORECARD_VALID, decision: str = P1_DECISION_VALID, review: str = P1_REVIEW_VALID) -> None:
    research_dir = os.path.join(tmpdir, ".sisyphus", "research", "p1")
    reviews_dir = os.path.join(tmpdir, ".sisyphus", "reviews")
    proofs_dir = os.path.join(tmpdir, "docs", "security-proofs", "p1")
    os.makedirs(research_dir, exist_ok=True)
    os.makedirs(reviews_dir, exist_ok=True)
    os.makedirs(proofs_dir, exist_ok=True)

    with open(os.path.join(research_dir, "scorecard.md"), "w", encoding="utf-8") as f:
        _ = f.write(scorecard)
    with open(os.path.join(research_dir, "RG-P1-decision.md"), "w", encoding="utf-8") as f:
        _ = f.write(decision)
    with open(os.path.join(reviews_dir, "p1-scorecard-review.md"), "w", encoding="utf-8") as f:
        _ = f.write(review)


def test_p1_research_gate_scorecard_requires_all_candidates_and_consistent_primary():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "scorecard"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-research-gate/scorecard" in out, out


def test_p1_research_gate_scorecard_fails_when_primary_not_top_ranked():
    bad_scorecard = P1_SCORECARD_VALID.replace("| SLAP | 4.00 | 3.75 | 4.50 | 3.25 | 4.50 | 3.00 | 3.88 | 1 |", "| SLAP | 4.00 | 3.75 | 4.50 | 3.25 | 4.50 | 3.00 | 3.70 | 2 |")
    bad_scorecard = bad_scorecard.replace("| Greyhound | 3.50 | 4.75 | 4.00 | 2.50 | 4.50 | 2.50 | 3.76 | 2 |", "| Greyhound | 3.50 | 4.75 | 4.00 | 2.50 | 4.50 | 2.50 | 3.80 | 1 |")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir, scorecard=bad_scorecard)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "scorecard"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "top-ranked" in out, out


def test_p1_research_gate_scorecard_fails_when_weighted_total_arithmetic_is_wrong():
    bad_scorecard = P1_SCORECARD_VALID.replace("| Greyhound | 3.50 | 4.75 | 4.00 | 2.50 | 4.50 | 2.50 | 3.76 | 2 |", "| Greyhound | 3.50 | 4.75 | 4.00 | 2.50 | 4.50 | 2.50 | 3.40 | 2 |")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir, scorecard=bad_scorecard)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "scorecard"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "weighted total mismatch" in out.lower(), out


def test_p1_research_gate_decision_requires_consistency_with_scorecard():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "decision"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-research-gate/decision" in out, out


def test_p1_research_gate_decision_fails_on_primary_mismatch():
    bad_decision = P1_DECISION_VALID.replace("**Primary frozen for P1:** SLAP", "**Primary frozen for P1:** Greyhound")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir, decision=bad_decision)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "decision"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "primary mismatch" in out.lower(), out


def test_p1_research_gate_review_requires_required_sections_and_consistency():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "scorecard-review"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-research-gate/scorecard-review" in out, out


def test_p1_research_gate_review_fails_without_primary_reference():
    bad_review = P1_REVIEW_VALID.replace("SLAP is the top-ranked candidate.", "A top-ranked candidate exists.")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_gate_fixture_files(tmpdir, review=bad_review)
        rc, out, _ = run_script_in_cwd(
            "p1-research-gate.py", tmpdir, "--check", "scorecard-review"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "primary reference" in out.lower(), out


P1_BENCH_PLAN_VALID = textwrap.dedent("""\
    # P1 Benchmark Plan

    ## Benchmark Matrix

    | n | q bits | N | B_e | stack |
    | --- | ---: | ---: | ---: | --- |
    | 128 | 109 | 2048 | 32 | SLAP primary |
    | 256 | 109 | 4096 | 32 | Greyhound fallback |
    | 512 | 218 | 4096 | 48 | SLAP primary |
    | 1024 | 218 | 8192 | 64 | Greyhound fallback |

    ## Advisory Thresholds

    - Prover time
    - Proof size
    - Verifier time
    - Peak memory

    ## Measurement Protocol

    - fixed hardware fingerprint
""")


P1_MIGRATION_PLAN_VALID = textwrap.dedent("""\
    # P1 Migration Plan

    ## Rollout Phases

    - Phase 1: RED tests behind `real-nizk`
    - Phase 2: GREEN impl shipped; surrogate annotated
    - Phase 3: CI default flips to `real-nizk` and surrogate stays behind `surrogate-decrypt-share`
    - Phase 4: retire only after just p1-impl-gate plus 30 consecutive calendar days of green CI

    ## Feature Flag Schedule

    - default flips to `real-nizk`

    ## Surrogate Retirement

    - retire `surrogate-decrypt-share` after implementation gate + 30 consecutive green CI days

    ## Rollback Criteria

    - pivot to Greyhound or Rust-in-zkVM fallback on threshold breach
""")


P1_DESIGN_REVIEW_VALID = textwrap.dedent("""\
    # External Advisor Memo — DG-P1

    ## Summary

    VERDICT: APPROVE

    ## Bench Coverage

    - Covers all required benchmark dimensions.

    ## Migration Safety

    - Uses the required feature flags.

    ## Rollback Completeness

    - Names Greyhound and Rust-in-zkVM pivots.

    ## Gate Decision

    - Ready for design-gate pass.
""")


def write_p1_design_gate_fixture_files(
    tmpdir: str,
    bench_plan: str = P1_BENCH_PLAN_VALID,
    migration_plan: str = P1_MIGRATION_PLAN_VALID,
    review_memo: str = P1_DESIGN_REVIEW_VALID,
) -> None:
    design_dir = os.path.join(tmpdir, ".sisyphus", "design", "p1")
    reviews_dir = os.path.join(tmpdir, ".sisyphus", "reviews")
    os.makedirs(design_dir, exist_ok=True)
    os.makedirs(reviews_dir, exist_ok=True)
    with open(os.path.join(design_dir, "bench-plan.md"), "w", encoding="utf-8") as f:
        _ = f.write(bench_plan)
    with open(os.path.join(design_dir, "migration-plan.md"), "w", encoding="utf-8") as f:
        _ = f.write(migration_plan)
    with open(os.path.join(reviews_dir, "p1-design-gate-review.md"), "w", encoding="utf-8") as f:
        _ = f.write(review_memo)


def test_p1_design_gate_bench_plan_requires_required_headings():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "bench-plan"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-design-gate/bench-plan" in out, out


def test_p1_design_gate_bench_plan_fails_without_measurement_protocol_heading():
    bad_bench_plan = P1_BENCH_PLAN_VALID.replace("## Measurement Protocol\n", "## Measurement Notes\n")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir, bench_plan=bad_bench_plan)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "bench-plan"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "Measurement Protocol" in out, out


def test_p1_design_gate_bench_plan_fails_without_both_required_stacks():
    bad_bench_plan = P1_BENCH_PLAN_VALID.replace("SLAP primary", "Unknown stack")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir, bench_plan=bad_bench_plan)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "bench-plan"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "SLAP primary" in out, out


def test_p1_design_gate_migration_plan_requires_required_headings():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "migration-plan"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-design-gate/migration-plan" in out, out


def test_p1_design_gate_migration_plan_fails_without_rollback_heading():
    bad_migration_plan = P1_MIGRATION_PLAN_VALID.replace("## Rollback Criteria\n", "## Rollback Notes\n")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir, migration_plan=bad_migration_plan)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "migration-plan"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "Rollback Criteria" in out, out


def test_p1_design_gate_migration_plan_fails_without_required_feature_flags():
    bad_migration_plan = P1_MIGRATION_PLAN_VALID.replace("`real-nizk`", "`real-proof`")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir, migration_plan=bad_migration_plan)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "migration-plan"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "real-nizk" in out, out


def test_p1_design_gate_reviewer_memo_requires_required_sections():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "reviewer-memo"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p1-design-gate/reviewer-memo" in out, out


def test_p1_design_gate_reviewer_memo_fails_without_verdict():
    bad_review = P1_DESIGN_REVIEW_VALID.replace("VERDICT: APPROVE\n", "")
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p1_design_gate_fixture_files(tmpdir, review_memo=bad_review)
        rc, out, _ = run_script_in_cwd(
            "p1-design-gate.py", tmpdir, "--check", "reviewer-memo"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "VERDICT: APPROVE" in out, out


# ---------------------------------------------------------------------------
# p2-design-gate.py
# ---------------------------------------------------------------------------

P2_STACK_DECISION_VALID = textwrap.dedent("""\
    # P2 Stack Decision Memo

    ## Primary Stack
    LatticeFold+ remains the primary stack.

    ## Fallback Stacks
    MicroNova and Rust-in-zkVM remain available.

    ## Quantitative Comparison
    | Candidate | RLWE-native | Fold-depth@t=513 | Prover-mem-peak | Accum-size | Verifier-gas | PQ-posture | Audit-surface | Weighted-score |
    | --- | --- | --- | --- | --- | --- | --- | --- | --- |
    | LatticeFold+ | Yes | ~10 | projected | projected | projected | PQ-native | medium | 3.45 |

    ## Recursion Fit
    A fold depth of about 10 covers t=513 because 2^10 > 513.

    ## Reviewer Sign-off
    VERDICT: APPROVE
""")


P2_STACK_DECISION_MISSING_HEADING = P2_STACK_DECISION_VALID.replace(
    "## Recursion Fit\n", "## Recursion Notes\n"
)


def write_p2_design_gate_fixture_files(tmpdir: str, stack_decision: str = P2_STACK_DECISION_VALID) -> None:
    design_dir = os.path.join(tmpdir, ".sisyphus", "design", "p2")
    os.makedirs(design_dir, exist_ok=True)
    with open(os.path.join(design_dir, "stack-decision.md"), "w", encoding="utf-8") as f:
        _ = f.write(stack_decision)


def test_p2_design_gate_stack_decision_requires_required_headings_and_verdict():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p2_design_gate_fixture_files(tmpdir)
        rc, out, _ = run_script_in_cwd(
            "p2-design-gate.py", tmpdir, "--check", "stack-decision"
        )
        assert rc == 0, f"Expected 0, got {rc}. Output: {out}"
        assert "PASS: p2-design-gate/stack-decision" in out, out
        evidence_path = os.path.join(tmpdir, ".sisyphus", "evidence", "p2-design", "stack-check.txt")
        assert os.path.exists(evidence_path), f"Expected evidence file at {evidence_path}"


def test_p2_design_gate_stack_decision_fails_without_required_heading():
    with tempfile.TemporaryDirectory() as tmpdir:
        write_p2_design_gate_fixture_files(tmpdir, stack_decision=P2_STACK_DECISION_MISSING_HEADING)
        rc, out, _ = run_script_in_cwd(
            "p2-design-gate.py", tmpdir, "--check", "stack-decision"
        )
        assert rc != 0, f"Expected non-zero, got {rc}. Output: {out}"
        assert "## Recursion Fit" in out, out
