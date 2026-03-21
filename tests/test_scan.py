from fastapi.testclient import TestClient
import pytest

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
                request=scanner.httpx.Request("GET", "https://www.python.org"),
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


class RecordingMockClient(MockClient):
    def __init__(self, responses: dict[str, str], headers: dict[str, str] | None, seen_headers: list[dict[str, str] | None]):
        super().__init__(responses)
        self.headers = headers
        self.seen_headers = seen_headers

    def get(self, url: str):
        self.seen_headers.append(self.headers)
        return super().get(url)


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
        "https://www.python.org": "<html lang='en'><body><a href='/about'>About</a></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post('/scan', json={"url": "https://www.python.org"})
    assert response.status_code == 200
    body = response.json()
    assert body["scan_mode"] == "url"
    assert body["totals"]["passes"] >= 1


def test_scan_requires_exactly_one_input():
    response = client.post('/scan', json={"url": "https://www.python.org", "html": "<html/>"})
    assert response.status_code == 422


def test_batch_scan(monkeypatch):
    responses = {
        "https://www.python.org": "<html lang='en'><body><a href='/about'>About</a></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post(
        '/scan/batch',
        json={
            "scans": [
                {"url": "https://www.python.org"},
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
    assert any("wcag22aa" in rule["standards"] for rule in body["rules"])


def test_standards_endpoint():
    response = client.get('/standards')
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert any(item["standard_id"] == "wcag22aa" and item["is_default"] for item in body["standards"])


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
        "https://developer.mozilla.org": "<html lang='en'><body><a href='/about'>About</a></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post(
        '/scan/batch',
        json={
            "webhook_url": "https://webhook.site/00000000-0000-0000-0000-000000000000",
            "scans": [
                {"url": "https://developer.mozilla.org"},
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
        "https://www.python.org": (
            "<html lang='en'><body>"
            "<a href='/about'>About</a>"
            "<a href='/downloads'>Downloads</a>"
            "</body></html>"
        ),
        "https://www.python.org/about": (
            "<html lang='en'><body><a href='/about/apps'>Apps</a><img src='logo.png' alt='Logo'></body></html>"
        ),
        "https://www.python.org/downloads": "<html><body><img src='map.png'></body></html>",
        "https://www.python.org/about/apps": "<html lang='en'><body>Apps</body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    response = client.post(
        '/jobs',
        json={
            "url": "https://www.python.org",
            "max_pages": 4,
            "max_depth": 2,
            "allowed_path_prefixes": ["/about"],
            "excluded_path_prefixes": ["/about/jobs"],
        },
    )
    assert response.status_code == 202
    job_id = response.json()["job_id"]

    job_response = client.get(f'/jobs/{job_id}')
    assert job_response.status_code == 200
    job = job_response.json()
    assert job["status"] == "complete"
    assert job["summary"]["pages_scanned"] == 3
    assert job["summary"]["max_depth_reached"] == 2
    assert job["max_depth"] == 2
    assert job["allowed_path_prefixes"] == ["/about"]
    assert job["summary"]["route_inventory"] == [
        "https://www.python.org",
        "https://www.python.org/about",
        "https://www.python.org/about/apps",
    ]
    assert len(job["results"]) == 3
    assert job["results"][1]["depth"] == 1
    assert job["results"][2]["depth"] == 2
    assert job["results"][2]["parent_url"] == "https://www.python.org/about"
    assert job["results"][2]["scan"]["score"] >= 0


def test_jobs_diff_reports_route_inventory_changes(monkeypatch):
    responses = {
        "https://www.w3.org": "<html lang='en'><body><a href='/about'>About</a></body></html>",
        "https://www.w3.org/about": "<html lang='en'><body>About</body></html>",
        "https://www.mozilla.org": "<html lang='en'><body><a href='/about'>About</a><a href='/contact'>Contact</a></body></html>",
        "https://www.mozilla.org/about": "<html lang='en'><body>About</body></html>",
        "https://www.mozilla.org/contact": "<html><body><img src='office.png'></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    baseline = client.post('/jobs', json={"url": "https://www.w3.org", "max_pages": 2})
    current = client.post('/jobs', json={"url": "https://www.mozilla.org", "max_pages": 3})
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
    assert "https://www.mozilla.org/contact" in diff["pages_added"]
    assert "https://www.w3.org/about" in diff["pages_removed"]
    assert diff["average_score_delta"] <= 0
    assert diff["page_score_changes"] == []


def test_jobs_diff_reports_page_level_violation_changes(monkeypatch):
    responses = {
        "https://www.amazon.com": "<html lang='en'><body><a href='/accessibility'>Accessibility</a></body></html>",
        "https://www.amazon.com/accessibility": "<html><body><img src='hero.png'></body></html>",
    }
    updated_responses = {
        "https://www.amazon.com": "<html lang='en'><body><a href='/accessibility'>Accessibility</a></body></html>",
        "https://www.amazon.com/accessibility": (
            "<html lang='en'><body><img src='hero.png' alt='Accessibility'><a href='/support'>Support</a></body></html>"
        ),
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))
    baseline = client.post('/jobs', json={"url": "https://www.amazon.com", "max_pages": 2})
    assert baseline.status_code == 202

    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(updated_responses))
    current = client.post('/jobs', json={"url": "https://www.amazon.com", "max_pages": 2})
    assert current.status_code == 202

    diff_response = client.post(
        '/jobs/diff',
        json={
            "baseline_job_id": baseline.json()["job_id"],
            "current_job_id": current.json()["job_id"],
        },
    )
    assert diff_response.status_code == 200
    page_changes = diff_response.json()["page_score_changes"]
    detail = next(item for item in page_changes if item["url"] == "https://www.amazon.com/accessibility")
    assert "image-alt" in detail["resolved_violations"]
    assert detail["new_violations"] == []
    assert detail["score_delta"] > 0


def test_create_job_respects_robots_txt_and_user_agent(monkeypatch):
    seen_headers: list[dict[str, str] | None] = []
    responses = {
        "https://www.microsoft.com/robots.txt": "User-agent: *\nDisallow: /private",
        "https://www.microsoft.com": (
            "<html lang='en'><body>"
            "<a href='/about'>About</a>"
            "<a href='/private'>Private</a>"
            "</body></html>"
        ),
        "https://www.microsoft.com/about": "<html lang='en'><body>About</body></html>",
    }

    def client_factory(**kwargs):
        return RecordingMockClient(responses, kwargs.get("headers"), seen_headers)

    monkeypatch.setattr(scanner.httpx, 'Client', client_factory)

    response = client.post(
        '/jobs',
        json={
            "url": "https://www.microsoft.com",
            "max_pages": 3,
            "user_agent": "AccessCheckQA/1.0",
            "respect_robots_txt": True,
        },
    )
    assert response.status_code == 202
    job = client.get(f"/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "complete"
    assert job["summary"]["route_inventory"] == [
        "https://www.microsoft.com",
        "https://www.microsoft.com/about",
    ]
    assert all(headers["User-Agent"] == "AccessCheckQA/1.0" for headers in seen_headers if headers)


def test_create_job_applies_request_delay(monkeypatch):
    sleeps: list[float] = []
    responses = {
        "https://www.apple.com/robots.txt": "",
        "https://www.apple.com": "<html lang='en'><body><a href='/store'>Store</a></body></html>",
        "https://www.apple.com/store": "<html lang='en'><body>Store</body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))
    monkeypatch.setattr(scanner.time, 'sleep', lambda seconds: sleeps.append(seconds))

    response = client.post(
        '/jobs',
        json={
            "url": "https://www.apple.com",
            "max_pages": 2,
            "request_delay_ms": 25,
        },
    )
    assert response.status_code == 202
    job = client.get(f"/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "complete"
    assert job["request_delay_ms"] == 25
    assert sleeps
    assert all(delay == 0.025 for delay in sleeps)


def test_cancel_job_marks_job_cancelled_when_polled_before_processing(monkeypatch):
    import app.main as main_module

    monkeypatch.setattr(main_module, 'process_crawl_job', lambda job_id: scanner.get_crawl_job(job_id))

    with TestClient(app) as delayed_client:
        response = delayed_client.post('/jobs', json={"url": "https://www.python.org", "max_pages": 2})
        assert response.status_code == 202
        job_id = response.json()["job_id"]

        cancel_response = delayed_client.delete(f'/jobs/{job_id}')
        assert cancel_response.status_code == 200
        cancelled = cancel_response.json()
        assert cancelled["status"] == "cancelled"


def test_get_unknown_job_returns_not_found():
    response = client.get('/jobs/not-a-real-job')
    assert response.status_code == 404


@pytest.mark.parametrize(
    "url",
    [
        "https://www.amazon.com",
        "https://www.apple.com",
        "https://www.microsoft.com",
    ],
)
def test_scan_live_public_websites(url):
    response = client.post('/scan', json={"url": url})
    assert response.status_code == 200
    body = response.json()
    assert body["scan_mode"] == "url"
    assert body["target"].rstrip("/") == url.rstrip("/")
    assert "coverage_disclaimer" in body
    assert 0 <= body["score"] <= 100
    assert body["totals"]["violations"] >= 0


def test_rule_detail_endpoint_returns_single_rule():
    response = client.get('/rules/image-alt')
    assert response.status_code == 200
    assert response.json()['rule_id'] == 'image-alt'



def test_custom_rule_set_can_be_created_listed_and_used_for_scan():
    create_response = client.post(
        '/rule-sets',
        json={
            'name': 'Enterprise Images Only',
            'description': 'Focus on image rules for a custom enterprise policy.',
            'include_rules': ['image-alt', 'html-has-lang'],
            'disable_rules': ['html-has-lang'],
        },
    )
    assert create_response.status_code == 201
    rule_set = create_response.json()
    assert rule_set['rule_count'] == 1

    list_response = client.get('/rule-sets')
    assert list_response.status_code == 200
    assert any(item['rule_set_id'] == rule_set['rule_set_id'] for item in list_response.json()['rule_sets'])

    scan_response = client.post(
        '/scan',
        json={
            'html': "<html><body><img src='x.png'></body></html>",
            'rule_set_id': rule_set['rule_set_id'],
        },
    )
    assert scan_response.status_code == 200
    body = scan_response.json()
    assert [item['rule_id'] for item in body['violations']] == ['image-alt']
    assert body['totals']['violations'] == 1



def test_scan_run_only_and_disable_rules_filter_results():
    response = client.post(
        '/scan',
        json={
            'html': "<html><body><img src='x.png'></body></html>",
            'run_only': ['image-alt', 'html-has-lang'],
            'disable_rules': ['image-alt'],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert [item['rule_id'] for item in body['violations']] == ['html-has-lang']


def test_audit_logs_capture_scan_and_rule_set_activity():
    create_response = client.post(
        '/rule-sets',
        json={
            'name': 'Audit Trail Policy',
            'include_rules': ['image-alt'],
        },
    )
    assert create_response.status_code == 201
    rule_set_id = create_response.json()['rule_set_id']

    scan_response = client.post(
        '/scan',
        json={
            'html': "<html><body><img src='x.png'></body></html>",
            'rule_set_id': rule_set_id,
        },
    )
    assert scan_response.status_code == 200

    logs_response = client.get('/audit-logs')
    assert logs_response.status_code == 200
    logs = logs_response.json()['audit_logs']
    assert any(item['event_type'] == 'rule_set.created' and item['resource_id'] == rule_set_id for item in logs)
    scan_log = next(item for item in logs if item['event_type'] == 'scan.completed')
    assert scan_log['metadata']['rule_set_id'] == rule_set_id

    detail_response = client.get(f"/audit-logs/{scan_log['event_id']}")
    assert detail_response.status_code == 200
    assert detail_response.json()['event_id'] == scan_log['event_id']



def test_create_job_with_rule_set_tracks_effective_rules(monkeypatch):
    responses = {
        'https://www.python.org': "<html><body><img src='x.png'></body></html>",
    }
    monkeypatch.setattr(scanner.httpx, 'Client', lambda **kwargs: MockClient(responses))

    rule_set_response = client.post(
        '/rule-sets',
        json={
            'name': 'Images only crawl',
            'include_rules': ['image-alt'],
        },
    )
    assert rule_set_response.status_code == 201
    rule_set_id = rule_set_response.json()['rule_set_id']

    response = client.post(
        '/jobs',
        json={
            'url': 'https://www.python.org',
            'max_pages': 1,
            'rule_set_id': rule_set_id,
        },
    )
    assert response.status_code == 202
    job = client.get(f"/jobs/{response.json()['job_id']}").json()
    assert job['status'] == 'complete'
    assert job['rule_set_id'] == rule_set_id
    assert job['effective_rules'] == ['image-alt']
    assert [item['rule_id'] for item in job['results'][0]['scan']['violations']] == ['image-alt']



def test_invalid_rule_id_returns_validation_error():
    response = client.post(
        '/scan',
        json={
            'html': '<html></html>',
            'run_only': ['not-a-real-rule'],
        },
    )
    assert response.status_code == 422
    assert 'Unsupported rule ids' in response.json()['detail']


def test_rule_detail_endpoint_includes_manual_review_rule():
    response = client.get('/rules/video-captions')
    assert response.status_code == 200
    assert response.json()['rule_id'] == 'video-captions'


def test_get_rule_set_returns_effective_rules():
    create_response = client.post(
        '/rule-sets',
        json={
            'name': 'Manual review bundle',
            'include_rules': ['video-captions', 'keyboard-operability', 'image-alt'],
            'disable_rules': ['image-alt'],
        },
    )
    assert create_response.status_code == 201
    rule_set_id = create_response.json()['rule_set_id']

    get_response = client.get(f'/rule-sets/{rule_set_id}')
    assert get_response.status_code == 200
    body = get_response.json()
    assert body['effective_rules'] == ['keyboard-operability', 'video-captions']
    assert body['rule_count'] == 2


def test_scan_rejects_empty_effective_rule_selection():
    response = client.post(
        '/scan',
        json={
            'html': '<html></html>',
            'run_only': ['image-alt'],
            'disable_rules': ['image-alt'],
        },
    )
    assert response.status_code == 422
    assert 'At least one effective rule' in response.json()['detail']


def test_create_rule_set_rejects_all_rules_disabled():
    response = client.post(
        '/rule-sets',
        json={
            'name': 'Invalid empty set',
            'include_rules': ['image-alt'],
            'disable_rules': ['image-alt'],
        },
    )
    assert response.status_code == 422
    assert 'At least one effective rule' in response.json()['detail']
