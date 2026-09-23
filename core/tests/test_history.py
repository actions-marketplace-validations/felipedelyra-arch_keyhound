import subprocess
from pathlib import Path

import pytest

from fresta.history import is_git_repository, scan_history


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo_with_removed_secret(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test User")

    target = tmp_path / "config.py"
    target.write_text('AWS_KEY = "AKIA2R7XQ4MPZK9TLW3B"\n')
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-q", "-m", "add config")

    target.write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-q", "-m", "move key to env")

    return tmp_path


def test_detects_repository(repo_with_removed_secret):
    assert is_git_repository(repo_with_removed_secret) is True


def test_non_repository(tmp_path):
    assert is_git_repository(tmp_path) is False


def test_finds_secret_removed_from_working_tree(repo_with_removed_secret):
    assert "AKIA2R7XQ4MPZK9TLW3B" not in (
        repo_with_removed_secret / "config.py"
    ).read_text()

    items = scan_history(repo_with_removed_secret)
    assert len(items) >= 1
    assert items[0].finding.rule_id == "aws-access-key"
    assert items[0].author == "Test User"


def test_reports_commit_metadata(repo_with_removed_secret):
    items = scan_history(repo_with_removed_secret)
    item = items[0]
    assert len(item.commit) == 8
    assert item.date.count("-") == 2
    assert str(item.finding.path) == "config.py"


def test_empty_on_plain_directory(tmp_path):
    assert scan_history(tmp_path) == []
    