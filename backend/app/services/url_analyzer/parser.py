from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit
import ipaddress
import re

import tldextract

extract_domain = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


@dataclass
class ParsedURL:
    original: str
    normalized: str
    hostname: str
    registered_domain: str
    scheme: str
    path: str
    query: str
    port: int | None
    is_ip: bool
    is_https: bool
    host_unicode: str


def parse_url(raw: str) -> ParsedURL:
    value = raw.strip()
    if len(value) > 2048:
        raise ValueError("URL exceeds the 2,048 character limit.")
    if any(ord(char) < 32 or char.isspace() for char in value):
        raise ValueError("URL must not contain spaces or control characters.")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value):
        raise ValueError("Include a supported http:// or https:// scheme.")
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only http and https URLs are supported.")
        hostname_raw = parts.hostname
        if not hostname_raw:
            raise ValueError("URL must include a hostname.")
        if parts.username is not None or parts.password is not None:
            # URL credentials are preserved as evidence but never used for authentication.
            pass
        host_unicode = hostname_raw.rstrip(".")
        try:
            ipaddress.ip_address(host_unicode)
            is_ip = True
            host_ascii = host_unicode
            registered = host_unicode
        except ValueError:
            is_ip = False
            try:
                host_ascii = host_unicode.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("Hostname could not be normalized with IDNA.") from exc
            result = extract_domain(host_ascii)
            registered = result.top_domain_under_public_suffix or host_ascii
            # Deterministic fallback for reserved/testing or newly delegated suffixes
            # absent from the bundled PSL snapshot (for example .example in docs/tests).
            if not result.suffix and "." in host_ascii:
                registered = ".".join(host_ascii.split(".")[-2:])
        port = parts.port
        display_host = f"[{host_ascii}]" if is_ip and ":" in host_ascii else host_ascii
        netloc = f"{display_host}{':' + str(port) if port is not None else ''}"
        if parts.username is not None:
            userinfo = parts.username + (":" + parts.password if parts.password else "")
            netloc = userinfo + "@" + netloc
        normalized = urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))
        return ParsedURL(value, normalized, host_ascii, registered, scheme, parts.path or "/", parts.query, port, is_ip, scheme == "https", host_unicode)
    except (ValueError, UnicodeError) as exc:
        if str(exc).startswith(("Only ", "URL ", "Include ", "Hostname ")):
            raise
        raise ValueError("Malformed URL. Check the scheme, hostname, and port.") from exc
