# tests/test_banner_checker.py
from unittest.mock import MagicMock, patch

import pytest
import requests

from BannerChecker import (
    SECURITY_HEADERS,
    BannerChecker,
    Disclosure,
    ScanError,
    ScanReport,
    find_banner_disclosures,
    find_missing_security_headers,
    find_mixed_content,
    main,
    normalize_url,
)


@pytest.fixture
def checker():
    return BannerChecker()


# --- normalize_url -----------------------------------------------------------
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("google.com", "https://google.com"),
        ("https://google.com", "https://google.com"),
        ("http://google.com", "http://google.com"),
        ("localhost:8080", "https://localhost:8080"),
        ("  example.com  ", "https://example.com"),
    ],
)
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected

@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com",
        "https:///missing-host",
        "http://[::1",
        "https://example.com:bad",
        "https://example.com:65536",
        "https://bad host/",
    ],
)
def test_normalize_url_rejects_malformed_urls(url):
    with pytest.raises(ValueError):
        normalize_url(url)


# --- headers -----------------------------------------------------------------
def test_find_banner_disclosures():
    headers = {"Server": "Apache", "X-Powered-By": "PHP", "Content-Type": "text/html"}
    result = find_banner_disclosures(headers)
    assert Disclosure("Server", "Apache") in result
    assert Disclosure("X-Powered-By", "PHP") in result
    assert len(result) == 2


def test_banner_header_match_is_case_insensitive():
    assert find_banner_disclosures({"server": "nginx"}) == [Disclosure("Server", "nginx")]


def test_find_missing_security_headers():
    headers = {"X-Frame-Options": "DENY", "content-type": "text/html"}
    missing = find_missing_security_headers(headers)
    assert "Content-Security-Policy" in missing
    assert "X-Frame-Options" not in missing


def test_no_missing_headers_when_all_present():
    headers = {h: "x" for h in SECURITY_HEADERS}
    assert find_missing_security_headers(headers) == []


# --- mixed content -----------------------------------------------------------
def test_find_mixed_content():
    html = """
    <html><body>
        <img src="http://example.com/image.jpg">
        <script src="https://safe.com/script.js"></script>
    </body></html>
    """
    result = find_mixed_content("https://test.com", html)
    assert len(result) == 1
    assert result[0].tag == "img"
    assert result[0].url == "http://example.com/image.jpg"


def test_mixed_content_ignores_non_https_pages():
    assert find_mixed_content("http://test.com", '<img src="http://a.com/x.png">') == []


def test_mixed_content_deduplicates_and_handles_srcset():
    html = """
    <img src="http://a.com/x.png"><img src="http://a.com/x.png">
    <img srcset="http://b.com/1.jpg 1x, /2.jpg 2x">
    """
    urls = {m.url for m in find_mixed_content("https://test.com", html)}
    assert urls == {"http://a.com/x.png", "http://b.com/1.jpg"}


def test_mixed_content_skips_non_loading_links():
    html = """
    <link rel="canonical" href="http://d.com/">
    <link rel="stylesheet" href="http://e.com/s.css">
    <a href="http://g.com">plain link</a>
    """
    result = find_mixed_content("https://test.com", html)
    assert [m.url for m in result] == ["http://e.com/s.css"]


def test_mixed_content_resolves_protocol_relative_urls_against_base():
    assert find_mixed_content("https://test.com", '<script src="//cdn.com/a.js"></script>') == []


# --- scan --------------------------------------------------------------------
def make_response(url="https://test.com/", status=200, headers=None, text="<html></html>"):
    response = MagicMock()
    response.url = url
    response.status_code = status
    response.headers = headers if headers is not None else {}
    response.text = text
    return response


@patch("requests.Session.get")
def test_scan_success(mock_get, checker):
    mock_get.return_value = make_response(
        headers={"Server": "MockServer", "Content-Type": "text/html"},
        text='<img src="http://a.com/x.png">',
    )

    report = checker.scan("test.com")

    assert isinstance(report, ScanReport)
    assert report.status_code == 200
    assert report.final_url == "https://test.com/"
    assert Disclosure("Server", "MockServer") in report.banner_disclosures
    assert len(report.mixed_content) == 1
    assert report.has_findings


@patch("requests.Session.get")
def test_scan_inspects_error_responses(mock_get, checker):
    mock_get.return_value = make_response(status=500, headers={"Server": "Leaky/1.0"})
    report = checker.scan("test.com")
    assert report.status_code == 500
    assert report.banner_disclosures


@patch("requests.Session.get")
def test_scan_skips_mixed_content_for_non_html(mock_get, checker):
    mock_get.return_value = make_response(
        headers={"Content-Type": "application/json"}, text='<img src="http://a.com/x.png">'
    )
    assert checker.scan("test.com").mixed_content == []


@patch("requests.Session.get", side_effect=requests.ConnectionError("boom"))
def test_scan_raises_scan_error_on_network_failure(mock_get, checker):
    with pytest.raises(ScanError):
        checker.scan("test.com")


# --- CLI ---------------------------------------------------------------------
@patch("requests.Session.get")
def test_main_exit_codes(mock_get, capsys):
    mock_get.return_value = make_response(headers={h: "x" for h in SECURITY_HEADERS})
    assert main(["test.com"]) == 0

    mock_get.return_value = make_response(headers={})
    assert main(["test.com"]) == 1

    mock_get.side_effect = requests.ConnectionError("boom")
    assert main(["test.com"]) == 2
