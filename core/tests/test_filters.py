from fresta.filters import (
    is_ignored_path,
    is_known_example,
    is_noise,
    is_placeholder,
    load_ignore_patterns,
)


def test_placeholder_variants():
    for value in ("xxxxxxxx", "<your-key-here>", "${API_KEY}", "CHANGEME", "aaaaaaaaaa"):
        assert is_placeholder(value) is True


def test_real_secret_is_not_placeholder():
    assert is_placeholder("AKIA2R7XQ4MPZK9TLW3B") is False


def test_empty_is_noise():
    assert is_noise("   ") is True


def test_known_example_is_filtered():
    assert is_known_example("AKIAIOSFODNN7EXAMPLE") is True
    assert is_noise("AKIAIOSFODNN7EXAMPLE") is True


def test_load_ignore_skips_comments(tmp_path):
    (tmp_path / ".frestaignore").write_text("# comment\n\ndocs/\n*.lock\n")
    assert load_ignore_patterns(tmp_path) == ["docs/", "*.lock"]


def test_missing_ignore_file_returns_empty(tmp_path):
    assert load_ignore_patterns(tmp_path) == []


def test_directory_pattern_matches(tmp_path):
    target = tmp_path / "docs" / "example.md"
    assert is_ignored_path(target, tmp_path, ["docs/"]) is True


def test_glob_pattern_matches(tmp_path):
    target = tmp_path / "src" / "yarn.lock"
    assert is_ignored_path(target, tmp_path, ["*.lock"]) is True


def test_unmatched_path_is_kept(tmp_path):
    target = tmp_path / "src" / "config.py"
    assert is_ignored_path(target, tmp_path, ["docs/", "*.lock"]) is False