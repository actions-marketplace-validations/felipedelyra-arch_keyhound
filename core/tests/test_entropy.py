import pytest

from fresta.entropy import is_high_entropy, shannon_entropy


def test_empty_string():
    assert shannon_entropy("") == 0.0


def test_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaa") == 0.0


def test_two_alternating_chars():
    assert shannon_entropy("abababab") == pytest.approx(1.0)


def test_short_password_rejected_by_length():
    assert is_high_entropy("senha123") is False


def test_aws_key_accepted():
    assert is_high_entropy("AKIA2R7XQ4MPZK9TLW3B") is True


def test_length_gate_runs_before_entropy():
    """Texto curto é rejeitado mesmo com entropia alta."""
    assert is_high_entropy("aB3$xY9") is False


def test_low_variety_text_rejected():
    """Pouca variedade de caracteres derruba a entropia."""
    assert is_high_entropy("aaaa bbbb aaaa bbbb aaaa") is False