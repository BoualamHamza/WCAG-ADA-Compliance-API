from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_html_mode_and_warning():
    response = client.post(
        '/scan',
        json={"html": "<html><body><img src='x.png'></body></html>", "include_remediation": True},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["scan_mode"] == "html"
    assert body["static_scan_warning"] is True
    assert body["totals"]["violations"] >= 1
    assert body["violations"][0]["remediation"]


def test_scan_url_mode():
    response = client.post('/scan', json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["scan_mode"] == "url"


def test_scan_requires_exactly_one_input():
    response = client.post('/scan', json={"url": "https://example.com", "html": "<html/>"})
    assert response.status_code == 422


def test_batch_scan():
    response = client.post(
        '/scan/batch',
        json={
            "scans": [
                {"url": "https://example.com"},
                {"html": "<html><body><img src='x.png'></body></html>"},
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_scans"] == 2
    assert len(body["results"]) == 2


def test_rules_endpoint():
    response = client.get('/rules')
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert any(rule["rule_id"] == "image-alt" for rule in body["rules"])


def test_scan_remediation_detail_levels():
    html = "<html><body><img src='x.png'></body></html>"
    brief = client.post(
        '/scan',
        json={
            "html": html,
            "include_remediation": True,
            "remediation_detail_level": "brief",
        },
    )
    verbose = client.post(
        '/scan',
        json={
            "html": html,
            "include_remediation": True,
            "remediation_detail_level": "verbose",
        },
    )

    assert brief.status_code == 200
    assert verbose.status_code == 200
    brief_text = brief.json()["violations"][0]["remediation"]
    verbose_text = verbose.json()["violations"][0]["remediation"]
    assert brief_text != verbose_text
    assert len(verbose_text) > len(brief_text)


def test_scan_remediation_locale_support_and_fallback():
    html = "<html><body><img src='x.png'></body></html>"
    es_response = client.post(
        '/scan',
        json={
            "html": html,
            "include_remediation": True,
            "locale": "es-MX",
        },
    )
    fallback_response = client.post(
        '/scan',
        json={
            "html": html,
            "include_remediation": True,
            "locale": "fr",
        },
    )

    assert es_response.status_code == 200
    assert fallback_response.status_code == 200

    es_remediation = es_response.json()["violations"][0]["remediation"]
    fallback_remediation = fallback_response.json()["violations"][0]["remediation"]

    assert "Agrega" in es_remediation
    assert fallback_remediation == 'Add a meaningful alt attribute, or alt="" for decorative images.'
