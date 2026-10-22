from collections import Counter
from urllib.parse import unquote
import math
import re

from app.core.config import BRANDS
from app.services.url_analyzer.parser import ParsedURL

WEIGHTS = {"critical": 52, "high": 34, "medium": 17, "low": 7}


def finding(rule_id, name, category, severity, explanation, evidence, recommendation, limitations="A heuristic indicator can occur on legitimate URLs and is not proof of maliciousness."):
    return {"rule_id": rule_id, "name": name, "category": category, "severity": severity, "explanation": explanation, "evidence": evidence, "recommendation": recommendation, "source": "heuristic", "limitations": limitations}


def analyze(parsed: ParsedURL) -> list[dict]:
    url, host = parsed.original, parsed.hostname
    findings = []
    if len(url) > 180:
        findings.append(finding("URL-LENGTH", "Unusually long URL", "Structure", "medium", "Long URLs can obscure the destination or contain tracking and redirect parameters.", [f"URL length: {len(url)} characters (review threshold: 180)."], "Inspect the hostname and each redirect parameter before opening."))
    labels = host.split(".")
    if len(labels) >= 5 and not parsed.is_ip:
        findings.append(finding("HOST-SUBDOMAINS", "Many hostname labels", "Structure", "medium", "Several subdomain labels can make the actual registered domain harder to notice.", [f"Hostname has {len(labels) - 2} labels before the public suffix.", f"Registered domain: {parsed.registered_domain}."] if len(labels) > 2 else [f"Hostname has {len(labels)} labels."], "Read the registered domain from right to left; subdomains do not establish ownership of a brand."))
    if "@" in urlsplit_safe_netloc(url):
        findings.append(finding("URL-CREDENTIALS", "Credentials in URL", "Obfuscation", "high", "The @ delimiter can make text before it look like the destination even though it is user information.", ["An @ delimiter appears in the authority component."], "Do not open until you have confirmed the hostname shown after @."))
    if parsed.is_ip:
        findings.append(finding("HOST-IP", "IP address hostname", "Infrastructure", "medium", "The URL uses a numeric IP address instead of a domain name.", [f"Hostname: {host}"], "Confirm that the IP is an expected destination through a trusted channel."))
    if parsed.port and parsed.port not in {80, 443, 8080, 8443}:
        findings.append(finding("UNUSUAL-PORT", "Uncommon port", "Structure", "low", "The URL specifies a port that is uncommon for ordinary web traffic.", [f"Port: {parsed.port}"], "Check whether this service and port are expected."))
    pairs = [p for p in parsed.query.split("&") if p]
    if len(pairs) >= 12:
        findings.append(finding("QUERY-VOLUME", "Large number of query parameters", "Structure", "medium", "Many query parameters may carry tracking, redirects, or opaque state.", [f"Query parameter count: {len(pairs)}."], "Review redirect and destination parameters without sharing sensitive values."))
    encoded = re.findall(r"%[0-9a-fA-F]{2}", url)
    if len(encoded) >= 3:
        finding_sev = "high" if re.search(r"%25[0-9a-fA-F]{2}", url, re.I) else "low"
        findings.append(finding("PERCENT-ENCODING", "Percent-encoded characters", "Obfuscation", finding_sev, "Encoded URL characters can be normal, but dense or nested encoding can conceal the represented text.", [f"Found {len(encoded)} percent-encoded byte sequences.", f"One decode preview: {unquote(url)[:180]}"], "Compare the encoded and decoded representations; decoded text is shown for inspection only."))
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(finding("PUNYCODE-HOST", "Punycode hostname", "Impersonation", "medium", "The hostname includes an IDNA-encoded label that may render as Unicode in some applications.", [f"ASCII hostname: {host}", f"Unicode input form: {parsed.host_unicode}"], "Compare the ASCII and displayed Unicode hostname carefully."))
    if not parsed.is_ip:
        core = parsed.registered_domain.split(".")[0].lower()
        for brand in sorted(BRANDS):
            if brand in host.lower() and brand not in core:
                findings.append(finding("BRAND-SUBDOMAIN", "Brand name outside registered domain", "Impersonation", "high", "A configured brand name appears in a hostname label, while the registered domain belongs to a different name.", [f"Brand-like label: {brand}", f"Registered domain: {parsed.registered_domain}"], "Visit the organization using a known bookmark or type its address manually. Brand resemblance is not proof of malicious intent."))
                break
        if core not in BRANDS:
            lookalike = next((brand for brand in sorted(BRANDS) if _near_brand(core, brand)), None)
            if lookalike:
                findings.append(finding("BRAND-LOOKALIKE", "Possible brand lookalike domain", "Impersonation", "medium", "The registered domain is close in spelling to a configured brand reference.", [f"Registered domain label: {core}", f"Similar configured brand: {lookalike}"], "Verify the registered domain through an official source. Similar spelling alone does not establish intent."))
    suspicious_ext = re.search(r"\.(?:exe|scr|bat|cmd|js|vbs|msi|apk)(?:$|[?#])", parsed.path + "?" + parsed.query, re.I)
    if suspicious_ext:
        findings.append(finding("EXECUTABLE-PATH", "Executable-like file extension", "Content", "medium", "The path or query contains a file extension commonly associated with downloadable or executable content.", [f"Matched extension: {suspicious_ext.group(0).split('?')[0]}"], "Do not download or run unexpected files; verify the sender and file through a separate channel."))
    if not parsed.is_ip and len(labels) >= 2:
        char_count = Counter(c for c in host if c.isalpha())
        entropy = -sum((n / sum(char_count.values())) * math.log2(n / sum(char_count.values())) for n in char_count.values()) if char_count else 0
        if entropy > 3.8 and len(host) >= 24:
            findings.append(finding("HOST-ENTROPY", "Unusual hostname composition", "Structure", "low", "The hostname has a varied character distribution that is less common for ordinary brand and service domains.", [f"Hostname entropy: {entropy:.2f} bits per character; hostname length: {len(host)}."], "Inspect the registered domain and source of the link."))
    return findings


def urlsplit_safe_netloc(url):
    from urllib.parse import urlsplit
    try:
        return urlsplit(url).netloc
    except ValueError:
        return ""


def _near_brand(core: str, brand: str) -> bool:
    if abs(len(core) - len(brand)) > 1 or core == brand:
        return False
    # One edit or adjacent transposition catches obvious examples without a fuzzy dependency.
    if len(core) == len(brand):
        diffs = [i for i, (a, b) in enumerate(zip(core, brand)) if a != b]
        return len(diffs) == 1 or (len(diffs) == 2 and diffs[1] == diffs[0] + 1 and core[diffs[0]] == brand[diffs[1]] and core[diffs[1]] == brand[diffs[0]])
    short, long = (core, brand) if len(core) < len(brand) else (brand, core)
    i = j = skips = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]: i += 1; j += 1
        else: skips += 1; j += 1
    return skips + (len(long) - j) <= 1
