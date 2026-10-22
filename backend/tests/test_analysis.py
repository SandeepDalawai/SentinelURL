import os
import tempfile

import pytest

from app.services.detection_rules.rules import analyze
from app.services.risk_scoring.scorer import score
from app.services.url_analyzer.parser import parse_url


def test_registered_domain_does_not_trust_misleading_subdomain():
    parsed = parse_url("https://paypal.com.attacker.example/login")
    assert parsed.registered_domain == "attacker.example"
    findings = analyze(parsed)
    assert any(item["rule_id"] == "BRAND-SUBDOMAIN" for item in findings)


def test_ip_hostname_and_unusual_port_are_explained():
    parsed = parse_url("http://203.0.113.10:9090/a")
    ids = {item["rule_id"] for item in analyze(parsed)}
    assert {"HOST-IP", "UNUSUAL-PORT"} <= ids


def test_ipv6_hostname_keeps_brackets_when_normalized():
    parsed = parse_url("https://[2001:db8::1]:8443/login")
    assert parsed.normalized == "https://[2001:db8::1]:8443/login"


def test_encoding_and_punycode_flags():
    encoded = analyze(parse_url("https://example.com/%252F%252F%252Flogin"))
    assert any(item["rule_id"] == "PERCENT-ENCODING" and item["severity"] == "high" for item in encoded)
    idn = analyze(parse_url("https://xn--pple-43d.com/account"))
    assert any(item["rule_id"] == "PUNYCODE-HOST" for item in idn)


@pytest.mark.parametrize("value", ["javascript:alert(1)", "//example.com", "https:///path", "https://has space.example", "ftp://example.com"])
def test_rejects_unsupported_or_malformed_urls(value):
    with pytest.raises(ValueError):
        parse_url(value)


def test_score_deduplicates_rule_ids_and_caps_at_100():
    findings = [{"rule_id": "HOST-IP", "severity": "high", "category": "Infrastructure", "name": "IP"}] * 5
    points, level, reasons = score(findings)
    assert points <= 100
    assert level in {"Low", "Medium", "High", "Critical"}
    assert sum("weighted points" in reason for reason in reasons) == 1


def test_no_findings_does_not_claim_safety():
    points, level, reasons = score([])
    assert (points, level) == (0, "Low")
    assert "does not guarantee" in reasons[0]


def test_url_credentials_are_detected():
    findings = analyze(parse_url("https://trusted.example@attacker.example/"))
    assert any(item["rule_id"] == "URL-CREDENTIALS" for item in findings)
