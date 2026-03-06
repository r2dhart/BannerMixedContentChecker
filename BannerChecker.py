#!/usr/bin/env python3
import argparse
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

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


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def check_headers(url: str):
    print("\n=== Header & Banner Check ===")
    try:
        resp = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error fetching URL: {e}")
        return None, None

    print(f"[+] HTTP status: {resp.status_code}")
    headers = {k.lower(): v for k, v in resp.headers.items()}

    print("\n--- Banner Disclosure ---")
    for h in BANNER_HEADERS:
        key = h.lower()
        if key in headers:
            print(f"[!] {h}: {headers[key]}  (Information disclosure)")
        else:
            print(f"[+] {h}: not present")

    print("\n--- Security Headers ---")
    missing = []
    for h, desc in RECOMMENDED_SECURITY_HEADERS.items():
        key = h.lower()
        if key in headers:
            print(f"[+] {h}: PRESENT -> {headers[key]}")
        else:
            print(f"[!] {h}: MISSING ({desc})")
            missing.append(h)

    return resp.text, missing


def check_mixed_content(url: str, html: str):
    print("\n=== Mixed Content Check ===")
    soup = BeautifulSoup(html, "html.parser")
    mixed = []

    for tag, attr in RESOURCE_TAGS.items():
        for element in soup.find_all(tag):
            src = element.get(attr)
            if not src:
                continue

            absolute = urljoin(url, src)
            if absolute.startswith("http://"):
                mixed.append((tag, absolute))

    if mixed:
        print("[!] Mixed content detected:")
        for tag, link in mixed:
            print(f"    - <{tag}> → {link}")
    else:
        print("[+] No mixed content found.")

    return mixed


def main():
    parser = argparse.ArgumentParser(
        description="Check a website for banner exposure, security header issues, and mixed content."
    )
    #parser.add_argument("url", help="Target URL or hostname")
    #args = parser.parse_args()
    args = input("Enter the URL or hostname to check: ")

    url = normalize_url(args)
    print(f"[+] Checking: {url}")

    html, missing_headers = check_headers(url)

    if html:
        check_mixed_content(url, html)

    print("\n=== Summary ===")
    if missing_headers:
        print("[!] Missing security headers:")
        for h in missing_headers:
            print(f"    - {h}")
    else:
        print("[+] All recommended security headers present.")

    print("[+] Scan complete.\n")


if __name__ == "__main__":
    main()