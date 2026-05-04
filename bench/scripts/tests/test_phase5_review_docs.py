"""Review-follow-up documentation consistency tests."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_readme_matches_current_p3_status_and_reproducing_mentions_per_party_fit():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    reproducing = (REPO_ROOT / "REPRODUCING.md").read_text(encoding="utf-8")

    assert "trusted-signer surrogate" not in readme
    assert "UltraHonkVerifier" in readme
    assert "fit-loglog.py" in reproducing
    assert "per-party" in reproducing


def test_phase5_admin_provenance_file_records_deliverables_and_commit():
    evidence = (REPO_ROOT / ".sisyphus" / "evidence" / "phase5-admin-deliverables.md")

    assert evidence.is_file()

    text = evidence.read_text(encoding="utf-8")
    for deliverable in ("E1", "E2", "A1", "A2", "A3"):
        assert deliverable in text
    assert "4a1ca5a" in text
