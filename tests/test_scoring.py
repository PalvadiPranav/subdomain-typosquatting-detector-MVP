from app.scoring import score_hostname


def test_brand_plus_login_scores_for_review():
    result = score_hostname(
        "acme-login.github.io", "Acme", ["acme.example"], [], source="CT: crt.sh"
    )
    assert result["score"] >= 50
    assert result["tier"] == "review"
    assert any(signal["name"] == "Brand-name similarity" and signal["points"] > 0 for signal in result["signals"])


def test_official_domain_has_negative_evidence():
    result = score_hostname("portal.acme.example", "Acme", ["acme.example"])
    official = next(s for s in result["signals"] if s["name"] == "Official-domain evidence")
    assert official["points"] == -30


def test_score_is_bounded():
    result = score_hostname("xn--acme-login.pages.dev", "Acme", ["acme.example"], ["login", "account"], "CT: crt.sh")
    assert 0 <= result["score"] <= 100
    assert result["tier"] in {"low", "review", "high"}


def test_score_is_explainable():
    result = score_hostname("random.example.net", "Acme", ["acme.example"])
    assert result["signals"]
    assert all({"name", "points", "reason"} <= set(signal) for signal in result["signals"])
