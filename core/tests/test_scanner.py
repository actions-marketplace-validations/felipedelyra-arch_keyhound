from pathlib import Path

from keyhound.scanner import is_binary, iter_files, scan_directory

FIXTURES = Path(__file__).parent / "fixtures"


def test_finds_planted_secrets():
    findings = scan_directory(FIXTURES)
    ids = {f.rule_id for f in findings}
    expected = {
        "aws-access-key",
        "db-connection-string",
        "generic-password",
        "mercadopago-token",
        "asaas-key",
        "supabase-service-role",
        "cielo-merchant-key",
        "pix-key-evp",
        "a1-cert-password",
    }
    assert expected <= ids


def test_sorted_by_severity():
    findings = scan_directory(FIXTURES)
    weights = [f.severity.weight for f in findings]
    assert weights == sorted(weights, reverse=True)


def test_innocent_line_not_reported():
    findings = scan_directory(FIXTURES)
    assert all("1.0.0" not in f.value for f in findings)


def test_value_is_always_masked():
    findings = scan_directory(FIXTURES)
    for f in findings:
        if len(f.value) > 8:
            assert f.value not in f.masked()


def test_ignored_dir_is_skipped(tmp_path):
    (tmp_path / "node_modules").mkdir()
    target = tmp_path / "node_modules" / "x.js"
    target.write_text('key = "AKIA2R7XQ4MPZK9TLW3B"')
    assert target not in set(iter_files(tmp_path))


def test_binary_detection(tmp_path):
    binary = tmp_path / "bin.dat"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    assert is_binary(binary) is True