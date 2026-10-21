import pytest

from app.normalization import is_under_domain, normalize_hostname, registrable_domain


def test_normalize_case_trailing_dot_and_wildcard():
    assert normalize_hostname("*.Login.Example.org.") == "login.example.org"


def test_normalize_pasted_url():
    assert normalize_hostname("https://Login.Example.org/path?q=1") == "login.example.org"


def test_normalize_idn_to_punycode():
    assert normalize_hostname("bücher.example") == "xn--bcher-kva.example"


def test_rejects_invalid_label():
    with pytest.raises(ValueError):
        normalize_hostname("-bad.example.org")


def test_domain_suffix_match_is_label_aware():
    assert is_under_domain("login.example.org", "example.org")
    assert not is_under_domain("notexample.org", "example.org")


def test_registrable_domain_returns_value():
    assert registrable_domain("login.example.com") == "example.com"
