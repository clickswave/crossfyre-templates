"""The lab runner's own checks: python3 -m pytest labs, with PyYAML and pytest."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run  # noqa: E402


@pytest.fixture
def root(tmp_path):
    (tmp_path / "labs" / "app").mkdir(parents=True)
    (tmp_path / "labs" / "app" / "Dockerfile").write_text("FROM scratch\n")
    return tmp_path


def lab(**given):
    out = {"vulnerable": {"image": "app:1.0"}, "patched": {"image": "app:1.1"}}
    out.update(given)
    return out


def test_a_lab_this_runs_has_nothing_wrong(root):
    assert run.wrong(lab(), root) is None
    built = {"build": "labs/app", "args": {"version": "1.0"}}
    assert run.wrong(lab(vulnerable=built, port=3000, ready="/health", wait=300), root) is None


@pytest.mark.parametrize(
    "given, says",
    [
        ({"patched": None}, "it has no patched container"),
        ({"vulnerable": {"image": "a", "build": "labs/app"}}, "one of them"),
        ({"vulnerable": {}}, "one of them"),
        ({"vulnerable": {"image": "a", "tag": "b"}}, "keys this does not read"),
        ({"vulnerable": {"image": "a", "args": {"v": "1"}}}, "for a folder it builds"),
        ({"vulnerable": {"build": "labs/none"}}, "has no Dockerfile"),
        ({"ready": "health"}, "starting with /"),
        ({"port": "80"}, "are numbers"),
        ({"setup": []}, "keys this does not read"),
    ],
)
def test_a_lab_this_cannot_run_says_why(root, given, says):
    assert says in run.wrong(lab(**given), root)


def test_a_template_with_a_lab_that_cannot_run_stops_the_run(root):
    templates = root / "plessor"
    templates.mkdir()
    (templates / "a.yaml").write_text(
        "id: a\ninfo:\n  metadata:\n    lab: { vulnerable: { image: x } }\n"
    )
    (templates / "b.yaml").write_text("id: b\ninfo:\n  metadata:\n    category: cves\n")
    with pytest.raises(SystemExit, match="plessor/a.yaml: lab: it has no patched"):
        run.labs(templates, root)
    (templates / "a.yaml").write_text(
        "id: a\ninfo:\n  metadata:\n    lab: { vulnerable: { image: x }, patched: { image: y } }\n"
    )
    assert [tid for tid, _ in run.labs(templates, root)] == ["a"]


def test_the_findings_are_read_from_the_scan_and_its_error_stops_it():
    events = "\n".join(
        [
            json.dumps({"type": "log", "message": "starting"}),
            json.dumps({"type": "finding", "data": {"template": "CVE-1", "name": "x"}}),
            json.dumps({"type": "finding", "data": {"name": "a header check"}}),
            "not json",
            json.dumps({"type": "done"}),
        ]
    )
    assert run.found(events) == {"CVE-1"}
    with pytest.raises(run.Failed, match="no database"):
        run.found(json.dumps({"type": "error", "message": "no database"}))


def test_only_a_missed_vulnerable_lab_or_a_found_patched_one_is_wrong():
    assert run.verdict("t", "vulnerable", True) is None
    assert run.verdict("t", "patched", False) is None
    assert "did not find its vulnerable" in run.verdict("t", "vulnerable", False)
    assert "found its patched" in run.verdict("t", "patched", True)
