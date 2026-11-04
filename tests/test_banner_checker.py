# tests/test_banner_checker.py
import pytest
from unittest.mock import MagicMock, patch
from BannerChecker import BannerChecker, ScanReport, RECOMMENDED_SECURITY_HEADERS, BANNER_HEADERS

@pytest.fixture
def checker():
    return BannerChecker()

def test_normalize_url(checker):
    assert checker.normalize_url("google.com") == "https://google.com"
    assert checker.normalize_url("https://google.com") == "https://google.com"

def test_analyze_headers(checker):
    # Mock headers: has one banner (Server) but missing a security header (CSP)
    mock_headers = {
        "Server": "Apache",
        "X-Powered-By": "PHP",
        "Content-Type": "text/html"
    }
    report = ScanReport(url="test.com", status_code=200, html="<html></html>")

    checker._analyze_headers(mock_headers, report)

    # Check banners
    assert any(h == "Server" for h, val in report.banner_disclosures)
    # Check missing security headers (CSP should be missing)
    assert "Content-Security-Policy" in report.missing_security_headers

def test_analyze_mixed_content(checker):
    # Mock HTML with a mixed content link (http)
    html = """
    <html>
        <body>
            <img src="http://example.com/image.jpg">
            <script src="https://safe.com/script.js"></script>
        </body>
    </html>
    """
    report = ScanReport(url="https://test.com", status_code=200, html=html)

    checker._analyze_mixed_content("https://test.com", html, report)

    assert len(report.mixed_content) == 1
    assert report.mixed_content[0][0] == "img"
    assert "http://" in report.mixed_content[0][1]

@patch("requests.Session.get")
def test_run_scan_success(mock_get, checker):
    # Setup mock response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Server": "MockServer"}
    mock_response.text = "<html></html>"
    mock_get.return_value = mock_response

    report = checker.run_scan("http://test.com")

    assert report is not None
    assert report.status_code == 200
    assert "Server" in [h for h, v in report.banner_disclosures]
