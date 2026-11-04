# BannerMixedContentChecker 🚧

> **Disclaimer: This project is a Work in Progress (WIP).** 
> Features, logic, and reporting styles are subject to change as development continues. The results provided by this tool should be used for educational and auditing purposes only.

## Description
`BannerMixedContentChecker` is a Python-based security auditing tool designed to identify common information leaks and configuration issues in web servers. It performs three primary types of checks:

1.  **Banner Disclosure**: Identifies headers that reveal server software and versions (e.g., `Server`, `X-Powered-By`), which can be leveraged by attackers to target specific vulnerabilities.
2.  **Security Headers**: Checks for the presence of essential security headers like `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), and `X-Frame-Options`.
3.  **Mixed Content**: Scans the page HTML to identify non-secure (`http://`) resources being loaded on secure (`https://`) pages, which can compromise user security.

## Features
- [x] Automated URL normalization.
- [x] Banner header identification.
- [x] Security header auditing.
- [x] Mixed content detection.
- [x] Unit testing suite with `pytest`.
- [x] CI/CD integration via GitHub Actions.

## Prerequisites
- Python 3.10 or higher
- `pip` (Python package manager)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/BannerMixedContentChecker.git
   cd BannerMixedContentChecker
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

## Usage
Run the checker from your terminal by providing the target URL or hostname:
   ```bash
  python3 BannerChecker.py https://example.com

## Example Output
    ```bash
    === Scan Results for https://example.com ===
      [+] HTTP status: 200
    
      --- Banner Disclosure ---
      [!] Server: Apache/2.4.41 (Information disclosure)
    
      --- Security Headers ---
      [!] Content-Security-Policy: MISSING
      [!] X-Frame-Options: MISSING
    
      --- Mixed Content Check ---
      [!] Mixed content: <img> -> http://example.com/image.jpg
    
      === Summary ===
      [!] 2 security headers missing.
      [+] Scan complete.

## Testing
To run the unit tests locally, ensure you are in the project root and run:
    ```bash
    python3 -m pytest

## Contributing
As this is a work in progress, contributions are welcome! Please feel free to submit Pull Requests or open an Issue if you find a bug or have a suggestion for a new feature.
