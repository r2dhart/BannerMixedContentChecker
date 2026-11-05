#!/usr/bin/env python3
"""Check a website for banner disclosure, missing security headers and mixed content.

Exit codes: 0 = no findings, 1 = findings, 2 = scan failed.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from importlib.util import find_spec
from typing import Mapping
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup, SoupStrainer
from requests.structures import CaseInsensitiveDict

logger = logging.getLogger(__name__)

# --- Configuration -----------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS and prevent downgrade attacks",
    "Content-Security-Policy": "Helps prevent XSS and content injection",
    "X-Frame-Options": "Helps prevent clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts powerful browser features",
}

BANNER_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")

# tag -> attributes that can load a resource
RESOURCE_ATTRS = {
    "img": ("src", "srcset"),
    "script": ("src",),
    "link": ("href",),
    "iframe": ("src",),
    "audio": ("src",),
    "video": ("src", "poster"),
    "source": ("src", "srcset"),
    "embed": ("src",),
    "object": ("data",),
    "form": ("action",),
}

# <link> elements that actually load something (canonical, alternate, etc. don't)
LOADED_LINK_RELS = {
    "stylesheet", "icon", "shortcut", "apple-touch-icon", "preload",
    "modulepreload", "prefetch", "manifest", "mask-icon",
}

# lxml is several times faster than html.parser; use it when installed.
HTML_PARSER = "lxml" if find_spec("lxml") else "html.parser"


# --- Data model --------------------------------------------------------------
@dataclass(frozen=True)
class Disclosure:
    header: str
    value: str


@dataclass(frozen=True)
class MixedResource:
    tag: str
    url: str


@dataclass
class ScanReport:
    requested_url: str
    final_url: str
    status_code: int
    banner_disclosures: list[Disclosure] = field(default_factory=list)
    missing_security_headers: list[str] = field(default_factory=list)
    mixed_content: list[MixedResource] = field(default_factory=list)

    @property
    def is_https(self) -> bool:
        return urlsplit(self.final_url).scheme == "https"

    @property
    def has_findings(self) -> bool:
        return bool(self.banner_disclosures or self.missing_security_headers or self.mixed_content)


class ScanError(Exception):
    """Raised when the target could not be fetched."""


# --- Analysis (pure functions: easy to unit test) ----------------------------
def normalize_url(url: str) -> str:
    """Add https:// when no scheme is given. (urlparse mis-reads 'host:8080'.)"""
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")

    candidate = url if "://" in url else f"https://{url}"

    # Raw whitespace/control characters should be percent-encoded in a URL.
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F
        for char in candidate):
        raise ValueError("URL cannot contain whitespace or control characters")

    try:
        parts = urlsplit(candidate)
        port = parts.port  # Raises ValueError for invalid or out-of-range ports.
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if parts.scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https")
    if not parts.hostname:
        raise ValueError("URL must include a hostname")

    return candidate


def find_banner_disclosures(headers: Mapping[str, str]) -> list[Disclosure]:
    headers = CaseInsensitiveDict(headers)
    return [Disclosure(h, headers[h]) for h in BANNER_HEADERS if h in headers]


def find_missing_security_headers(headers: Mapping[str, str]) -> list[str]:
    headers = CaseInsensitiveDict(headers)
    return [h for h in SECURITY_HEADERS if h not in headers]


def _candidate_urls(attr: str, value: str | None) -> list[str]:
    if not value:
        return []
    if attr == "srcset":  # "a.jpg 1x, b.jpg 2x"
        return [part.split()[0] for part in value.split(",") if part.strip()]
    return [value.strip()]


def find_mixed_content(base_url: str, html: str) -> list[MixedResource]:
    """Return http:// resources referenced by an https:// page (deduplicated)."""
    if urlsplit(base_url).scheme != "https":
        return []  # mixed content only exists on HTTPS pages

    # Parse only the tags we care about, in one pass.
    soup = BeautifulSoup(html, HTML_PARSER, parse_only=SoupStrainer(list(RESOURCE_ATTRS)))
    found: dict[tuple[str, str], MixedResource] = {}

    for element in soup.find_all(True):
        if element.name == "link":
            rels = {r.lower() for r in element.get("rel", [])}
            if not rels & LOADED_LINK_RELS:
                continue
        for attr in RESOURCE_ATTRS[element.name]:
            for raw in _candidate_urls(attr, element.get(attr)):
                absolute = urljoin(base_url, raw)
                if absolute.lower().startswith("http://"):
                    found.setdefault((element.name, absolute), MixedResource(element.name, absolute))
    return list(found.values())


# --- Scanner -----------------------------------------------------------------
class BannerChecker:
    def __init__(self, timeout: float = 10.0, verify_tls: bool = True):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "BannerChecker/1.1"

    def scan(self, target: str) -> ScanReport:
        url = normalize_url(target)
        try:
            # No raise_for_status(): error pages still carry headers worth checking.
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_tls)
        except requests.RequestException as exc:
            raise ScanError(f"Error fetching {url}: {exc}") from exc

        report = ScanReport(
            requested_url=url,
            final_url=response.url,  # after redirects; correct base for relative URLs
            status_code=response.status_code,
            banner_disclosures=find_banner_disclosures(response.headers),
            missing_security_headers=find_missing_security_headers(response.headers),
        )

        # The HTML is analysed here and not stored on the report.
        if "html" in response.headers.get("Content-Type", "").lower():
            report.mixed_content = find_mixed_content(report.final_url, response.text)
        else:
            logger.debug("Skipping mixed-content check: non-HTML response")
        return report


# --- Output ------------------------------------------------------------------
def _print_section(title: str, items: list[str], ok_message: str) -> None:
    print(f"\n--- {title} ---")
    if items:
        for item in items:
            print(f"[!] {item}")
    else:
        print(f"[+] {ok_message}")


def print_report(report: ScanReport) -> None:
    print(f"\n=== Scan Results for {report.final_url} ===")
    if report.final_url != report.requested_url:
        print(f"[i] Redirected from {report.requested_url}")
    print(f"[+] HTTP status: {report.status_code}")

    _print_section(
        "Banner Disclosure",
        [f"{d.header}: {d.value} (Information disclosure)" for d in report.banner_disclosures],
        "No banner headers detected.",
    )
    _print_section(
        "Security Headers",
        [f"{h}: MISSING ({SECURITY_HEADERS[h]})" for h in report.missing_security_headers],
        "All recommended security headers present.",
    )
    if report.is_https:
        _print_section(
            "Mixed Content Check",
            [f"Mixed content: <{m.tag}> -> {m.url}" for m in report.mixed_content],
            "No mixed content found.",
        )
    else:
        print("\n--- Mixed Content Check ---\n[i] Skipped: page was not served over HTTPS.")

    print("\n=== Summary ===")
    print(f"[{'!' if report.banner_disclosures else '+'}] {len(report.banner_disclosures)} banner disclosure(s)")
    print(f"[{'!' if report.missing_security_headers else '+'}] {len(report.missing_security_headers)} security header(s) missing")
    print(f"[{'!' if report.mixed_content else '+'}] {len(report.mixed_content)} mixed-content resource(s)")
    print("[+] Scan complete.\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", help="Target URL or hostname")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")

    checker = BannerChecker(timeout=args.timeout, verify_tls=not args.insecure)
    try:
        report = checker.scan(args.url)
    except ScanError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print_report(report)
    return 1 if report.has_findings else 0


if __name__ == "__main__":
    sys.exit(main())
