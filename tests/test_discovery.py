from app import discovery


class FakeResponse:
    content = b"[]"

    def raise_for_status(self):
        return None

    def json(self):
        return [
            {"name_value": "acme-login.example.net\nportal.acme.example"},
            {"name_value": "*.acme-pay.example.org"},
            {"name_value": "unrelated.example.org"},
        ]


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return FakeResponse()


def test_ct_discovery_filters_official_domains_and_unrelated_results(monkeypatch):
    monkeypatch.setattr(discovery.httpx, "Client", FakeClient)
    result = discovery.discover_ct_candidates("Acme Demo", ["acme.example"], max_candidates=100)
    assert result["queries"] == 1
    assert result["candidates"] == ["acme-login.example.net", "acme-pay.example.org"]
    assert "CT lookup completed" in result["message"]
