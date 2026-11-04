#!/usr/bin/env python3
import argparse
import requests
import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# --- Configuration Constants ---
RECOMMENDED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS and prevent downgrade attacks",
    "Content-Security-Policy": "Helps prevent XSS and content injection",
    "X-Frame-Options": "Helps prevent clickjacking",
    "X-Content-Type-Options": "Prevents MIME sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts powerful browser features",
}

BANNER_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

RESOURCE_TAGS = {
    "img": "src",
    "script": "src",
    "link": "href",
    "iframe": "src",
    "audio": "src",
    "video": "src",
    "source": "src",
    "form": "action",
}

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ScanReport:
    url: str
    status_code: int
    html: str
    missing_security_headers: List[str] = field(default_factory=list)
    mixed_content: List[Tuple[str, str]] = field(default_factory=list)
    banner_disclosures: List[Tuple[str, str]] = field(default_factory=list)

class BannerChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BannerChecker/1.0"})

    def normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
        return url

    def run_scan(self, target_url: str) -> Optional[ScanReport]:
        url = self.normalize_url(target_url)
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            report = ScanReport(
                url=url,
                status_code=response.status_code,
                html=response.text
            )

            # Explicitly passing response.headers to avoid NameError
            self._analyze_headers(response.headers, report)
            self._analyze_mixed_content(url, report.html, report)

            return report
        except requests.RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            return None

    def _analyze_headers(self, received_headers: dict, report: ScanReport):
        # Normalize headers to lowercase for consistent comparison
        lower_headers = {k.lower(): v for k, v in received_headers.items()}

        # Check Banners
        for h in BANNER_HEADERS:
            key = h.lower()
            if key in lower_headers:
                report.banner_disclosures.append((h, lower_headers[key]))

        # Check Security Headers
        for h, desc in RECOMMENDED_SECURITY_HEADERS.items():
            key = h.lower()
            if key not in lower_headers:
                report.missing_security_headers.append(h)

    def _analyze_mixed_content(self, base_url: str, html: str, report: ScanReport):
        soup = BeautifulSoup(html, "html.parser")
        for tag, attr in RESOURCE_TAGS.items():
            for element in soup.find_all(tag):
                src = element.get(attr)
                if src:
                    absolute = urljoin(base_url, src)
                    if absolute.startswith("http://"):
                        report.mixed_content.append((tag, absolute))

def print_report(report: ScanReport):
    print(f"\n=== Scan Results for {report.url} ===")
    print(f"[+] HTTP status: {report.status_code}")

    print("\n--- Banner Disclosure ---")
    if report.banner_disclosures:
        for h, val in report.banner_disclosures:
            print(f"[!] {h}: {val} (Information disclosure)")
    else:
        print("[+] No banner headers detected.")

    print("\n--- Security Headers ---")
    if report.missing_security_headers:
        for h in report.missing_security_headers:
            print(f"[!] {h}: MISSING")
    else:
        print("[+] All recommended security headers present.")

    print("\n--- Mixed Content Check ---")
    if report.mixed_content:
        for tag, link in report.mixed_content:
            print(f"[!] Mixed content: <{tag}> -> {link}")
    else:
        print("[+] No mixed content found.")

def main():
    parser = argparse.ArgumentParser(description="Check a website for banner exposure, security header issues, and mixed content.")
    parser.add_argument("url", help="Target URL or hostname")
    args = parser.parse_args()

    checker = BannerChecker()
    report = checker.run_scan(args.url)

    if report:
        print_report(report)
        print("\n=== Summary ===")
        if report.missing_security_headers:
            print(f"[!] {len(report.missing_security_headers)} security headers missing.")
        else:
            print("[+] All recommended security headers present.")
        print("[+] Scan complete.\n")

if __name__ == "__main__":
    main()
