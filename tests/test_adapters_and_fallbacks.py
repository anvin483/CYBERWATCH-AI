from services.enrichment import enrich_ip
from services.sensor_adapters import adapt_event


def test_zeek_notice_adapter_normalizes_network_event():
    result = adapt_event({
        "ts": 1690000000,
        "_path": "notice",
        "note": "SSH::Password_Guessing",
        "msg": "Repeated failed login attempts",
        "id.orig_h": "203.0.113.8",
        "id.resp_h": "192.0.2.8",
    })
    assert result["event_type"] == "zeek-notice"
    assert result["src_ip"] == "203.0.113.8"
    assert "Password" in result["signature"]


def test_private_ip_enrichment_is_explicitly_non_geographic():
    result = enrich_ip("192.0.2.8")
    assert result["locationSource"] in {"private", "unavailable"}
    assert result["abuse"]["status"] in {"not_configured", "unavailable"}
