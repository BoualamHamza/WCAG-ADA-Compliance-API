from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from fastapi.testclient import TestClient
import pytest

from app.main import app


client = TestClient(app)


class _Handler(BaseHTTPRequestHandler):
    html = "<html lang='en'><head><title>Fixture</title></head><body><main><a href='/about'>About</a></main></body></html>"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.html.encode("utf-8"))

    def log_message(self, format, *args):  # noqa: A003
        return


@pytest.fixture()
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()


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


def test_scan_url_mode(local_server):
    response = client.post('/scan', json={"url": local_server})
    assert response.status_code == 200
    body = response.json()
    assert body["scan_mode"] == "url"
    assert body["totals"]["passes"] >= 1


def test_scan_requires_exactly_one_input():
    response = client.post('/scan', json={"url": "https://www.python.org", "html": "<html/>"})
    assert response.status_code == 422


def test_batch_scan(local_server):
    response = client.post(
        '/scan/batch',
        json={
            "scans": [
                {"url": local_server},
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
    assert body["count"] >= 50
    assert any(rule["rule_id"] == "image-alt" for rule in body["rules"])
    assert any("wcag22aa" in rule["standards"] for rule in body["rules"])


def test_standards_endpoint():
    response = client.get('/standards')
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert any(item["standard_id"] == "wcag22aa" and item["is_default"] for item in body["standards"])


def test_scan_detects_color_contrast_violation():
    html = """
    <html lang='en'><head><title>Contrast</title><style>p { color: #7a7a7a; background: #fff; }</style></head>
    <body><p>Low contrast text</p></body></html>
    """
    response = client.post('/scan', json={"html": html})
    assert response.status_code == 200
    assert any(item["rule_id"] == "color-contrast" for item in response.json()["violations"])


def test_scan_detects_missing_form_label():
    html = "<html lang='en'><head><title>Label</title></head><body><form><input type='text'></form></body></html>"
    response = client.post('/scan', json={"html": html})
    assert response.status_code == 200
    assert any(item["rule_id"] == "label" for item in response.json()["violations"])


def test_scan_passes_contain_real_rules():
    html = "<html lang='en'><head><title>Passes</title></head><body><main><img src='x.png' alt='x'><button>Save</button><a href='/home'>Home</a></main></body></html>"
    response = client.post('/scan', json={"html": html})
    assert response.status_code == 200
    passes = response.json()["passes"]
    assert any(item["rule_id"] == "button-name" for item in passes)


def test_scan_includes_structured_passes_and_incomplete_arrays_with_metadata():
    response = client.post(
        '/scan',
        json={
            "html": "<html lang='en'><head><title>Structured</title></head><body><img src='x.png' alt='x'><a href='/home'>Home</a><video src='movie.mp4'></video><div onclick='go()'>Open</div></body></html>",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["passes"], list)
    assert isinstance(body["incomplete"], list)
    assert body["totals"]["passes"] == len(body["passes"])
    assert body["totals"]["incomplete"] == len(body["incomplete"])
    assert all(0 <= item["confidence"] <= 1 for item in body["passes"] + body["incomplete"])


def test_batch_scan_supports_webhook_callback_registration_and_retry(local_server):
    response = client.post(
        '/scan/batch',
        json={
            "webhook_url": "https://webhook.site/00000000-0000-0000-0000-000000000000",
            "scans": [
                {"url": local_server},
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
            "current": {"html": "<html lang='en'><head><title>Fixed</title></head><body><img src='x.png' alt='logo'></body></html>"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["score_delta"] > 0
    assert "image-alt" in body["resolved_violations"]
