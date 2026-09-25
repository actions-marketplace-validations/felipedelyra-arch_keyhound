from datetime import datetime
from pathlib import Path

from typer.testing import CliRunner

from keyhound.cli import app
from keyhound.lgpd import to_html
from keyhound.models import Finding, Severity
from keyhound.scanner import scan_directory
from keyhound.validate import Status

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_DATE = datetime(2026, 9, 24, 10, 0)
runner = CliRunner()


def _finding(rule_id: str = "aws-access-key", path: str = "app.py") -> Finding:
    return Finding(
        rule_id=rule_id,
        path=Path(path),
        line=3,
        value="AKIA2R7XQ4MPZK9TLW3B",
        entropy=4.1,
        severity=Severity.CRITICAL,
    )


def _html(findings, **kwargs) -> str:
    return to_html(findings, Path("."), generated_at=FIXED_DATE, **kwargs)


def test_is_complete_html_document():
    html = _html([_finding()])
    assert html.startswith("<!DOCTYPE html>")
    assert 'lang="pt-BR"' in html
    assert "24/09/2026 10:00" in html


def test_cites_lgpd_articles():
    html = _html([_finding()])
    assert "13.709/2018" in html
    assert "Art. 46" in html
    assert "Art. 48" in html
    assert "não constitui parecer jurídico" in html


def test_never_leaks_raw_values():
    findings = scan_directory(FIXTURES)
    html = to_html(findings, FIXTURES, generated_at=FIXED_DATE)
    assert "AKIA2R7XQ4MPZK9TLW3B" not in html
    assert "MinhaSenh4Forte" not in html


def test_escapes_file_paths():
    html = _html([_finding(path="<script>alert(1)</script>.py")])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_escapes_client_name():
    html = _html([_finding()], client="<b>Loja</b>")
    assert "<b>Loja</b>" not in html
    assert "&lt;b&gt;Loja&lt;/b&gt;" in html


def test_clean_scan_message():
    html = _html([])
    assert "Nenhuma credencial exposta foi encontrada" in html
    assert "Credenciais encontradas" not in html


def test_active_credentials_are_highlighted():
    html = _html([_finding()], statuses=[Status.ACTIVE])
    assert "ATIVA" in html
    assert "revogada(s) imediatamente" in html


def test_supabase_service_role_gets_special_warning():
    html = _html([_finding(rule_id="supabase-service-role")])
    assert "Row Level Security" in html


def test_report_command_writes_file(tmp_path):
    output = tmp_path / "relatorio.html"
    result = runner.invoke(
        app, ["report", str(FIXTURES), "-o", str(output), "--client", "Cliente Teste"]
    )
    assert result.exit_code == 0
    assert output.exists()
    assert "Cliente Teste" in output.read_text(encoding="utf-8")