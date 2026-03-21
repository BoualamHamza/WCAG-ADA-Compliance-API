from fastapi.testclient import TestClient

from app.main import app
import app.scanner as scanner


client = TestClient(app)


class MockResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise scanner.httpx.HTTPStatusError(
                "mock error",
                request=scanner.httpx.Request("GET", "https://example.com"),
                response=scanner.httpx.Response(self.status_code),
            )


class MockClient:
    def __init__(self, responses: dict[str, str]):
        self.responses = responses

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str):
        normalized = url.rstrip('/') or url
        if normalized not in self.responses:
            raise scanner.httpx.ConnectError("mock connect error")
        return MockResponse(self.responses[normalized])


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


def test_scan_url_mode(monkeypatch):
    responses = {
        "https://example.com": "<html lang='en'><body><a href='/about'>About</a></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post('/scan', json={"url": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["scan_mode"] == "url"
    assert body["totals"]["passes"] >= 1


def test_scan_requires_exactly_one_input():
    response = client.post('/scan', json={"url": "https://example.com", "html": "<html/>"})
    assert response.status_code == 422


def test_batch_scan(monkeypatch):
    responses = {
        "https://example.com": "<html lang='en'><body><a href='/about'>About</a></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

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


def test_scan_includes_structured_passes_and_incomplete_arrays_with_metadata():
    response = client.post(
        '/scan',
        json={
            "html": "<html lang='en'><body><img src='x.png' alt='x'><a href='/home'>Home</a><video src='movie.mp4'></video><div onclick='go()'>Open</div></body></html>",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["passes"], list)
    assert isinstance(body["incomplete"], list)
    assert body["totals"]["passes"] == len(body["passes"])
    assert body["totals"]["incomplete"] == len(body["incomplete"])

    image_alt_pass = next(item for item in body["passes"] if item["rule_id"] == "image-alt")
    assert image_alt_pass["impact"] == "serious"
    assert 0 <= image_alt_pass["confidence"] <= 1

    video_captions_incomplete = next(item for item in body["incomplete"] if item["rule_id"] == "video-captions")
    assert video_captions_incomplete["impact"] == "serious"
    assert 0 <= video_captions_incomplete["confidence"] <= 1


def test_batch_scan_supports_webhook_callback_registration_and_retry(monkeypatch):
    responses = {
        "https://example.com": "<html lang='en'><body><a href='/about'>About</a></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post(
        '/scan/batch',
        json={
            "webhook_url": "https://webhook.site/00000000-0000-0000-0000-000000000000",
            "scans": [
                {"url": "https://example.com"},
                {"html": "<html><body><img src='x.png'></body></html>"},
            ],
        },
    )

    assert response.status_code == 200
    body = response.json()
    callback = body["callback"]
    assert callback is not None
    assert callback["status"] == "queued"
    assert callback["event"] == "scan.batch.completed"
    assert callback["total_scans"] == 2
    assert callback["attempts"] == 0
    assert callback["max_attempts"] == 3

    retry_response = client.post(f"/scan/batch/{callback['delivery_id']}/retry")
    assert retry_response.status_code == 200
    retry_callback = retry_response.json()["callback"]
    assert retry_callback["attempts"] == 1
    assert retry_callback["status"] == "retrying"
    assert len(retry_callback["history"]) == 1


def test_retry_unknown_delivery_id_returns_not_found():
    response = client.post('/scan/batch/not-a-real-id/retry')
    assert response.status_code == 404


def test_scan_diff_reports_delta_and_violation_changes():
    response = client.post(
        '/scan/diff',
        json={
            "baseline": {"html": "<html><body><img src='x.png'></body></html>"},
            "current": {"html": "<html lang='en'><body><img src='x.png' alt='logo'></body></html>"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["score_delta"] > 0
    assert "image-alt" in body["resolved_violations"]


def test_create_job_processes_real_route_inventory(monkeypatch):
    responses = {
        "https://example.com": "<html lang='en'><body><a href='/about'>About</a><a href='/contact'>Contact</a></body></html>",
        "https://example.com/about": "<html lang='en'><body><img src='logo.png' alt='Logo'></body></html>",
        "https://example.com/contact": "<html><body><img src='map.png'></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post('/jobs', json={"url": "https://example.com", "max_pages": 3})
    assert response.status_code == 202
    job_id = response.json()["job_id"]

    job_response = client.get(f'/jobs/{job_id}')
    assert job_response.status_code == 200
    job = job_response.json()
    assert job["status"] == "complete"
    assert job["summary"]["pages_scanned"] == 3
    assert job["summary"]["route_inventory"] == [
        "https://example.com",
        "https://example.com/about",
        "https://example.com/contact",
    ]
    assert len(job["results"]) == 3
    assert job["results"][2]["totals"]["violations"] >= 1


def test_jobs_diff_reports_route_inventory_changes(monkeypatch):
    responses = {
        "https://example.com": "<html lang='en'><body><a href='/about'>About</a></body></html>",
        "https://example.com/about": "<html lang='en'><body>About</body></html>",
        "https://example.org": "<html lang='en'><body><a href='/about'>About</a><a href='/contact'>Contact</a></body></html>",
        "https://example.org/about": "<html lang='en'><body>About</body></html>",
        "https://example.org/contact": "<html><body><img src='office.png'></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    baseline = client.post('/jobs', json={"url": "https://example.com", "max_pages": 2})
    current = client.post('/jobs', json={"url": "https://example.org", "max_pages": 3})
    assert baseline.status_code == 202
    assert current.status_code == 202

    diff_response = client.post(
        '/jobs/diff',
        json={
            "baseline_job_id": baseline.json()["job_id"],
            "current_job_id": current.json()["job_id"],
        },
    )
    assert diff_response.status_code == 200
    diff = diff_response.json()
    assert "https://example.org/contact" in diff["pages_added"]
    assert "https://example.com/about" in diff["pages_removed"]
    assert diff["average_score_delta"] <= 0


def test_cancel_job_marks_job_cancelled_when_polled_before_processing(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, 'process_crawl_job', lambda job_id: scanner.get_crawl_job(job_id))

    with TestClient(app) as delayed_client:
        response = delayed_client.post('/jobs', json={"url": "https://example.com", "max_pages": 2})
        assert response.status_code == 202
        job_id = response.json()["job_id"]

        cancel_response = delayed_client.delete(f'/jobs/{job_id}')
        assert cancel_response.status_code == 200
        cancelled = cancel_response.json()
        assert cancelled["status"] == "cancelled"


def test_get_unknown_job_returns_not_found():
    response = client.get('/jobs/not-a-real-job')
    assert response.status_code == 404
