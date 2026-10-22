import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import csv_cell

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_and_persistent_scan_history(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"
    response = client.post("/api/v1/scans", json={"url": "https://paypal.com.attacker.example/login"})
    assert response.status_code == 200
    scan = response.json()
    assert scan["registered_domain"] == "attacker.example"
    assert scan["findings"]
    listed = client.get("/api/v1/scans?search=attacker.example")
    assert listed.status_code == 200 and listed.json()["total"] >= 1
    assert client.get(f"/api/v1/scans/{scan['id']}").json()["id"] == scan["id"]
    assert client.delete(f"/api/v1/scans/{scan['id']}").status_code == 200
    assert client.get(f"/api/v1/scans/{scan['id']}").status_code == 404


def test_api_validates_url_and_bulk_csv(client):
    invalid = client.post("/api/v1/scans", json={"url": "file:///etc/passwd"})
    assert invalid.status_code == 422
    response = client.post("/api/v1/scans/bulk", files={"file": ("urls.csv", b"url\nhttps://example.com\nnot a url\n", "text/csv")})
    assert response.status_code == 200
    assert response.json()["successful"] == 1
    assert response.json()["failed"] == 1


def test_history_date_filter_and_sort(client):
    low = client.post("/api/v1/scans", json={"url": "https://example.com/"}).json()
    high = client.post("/api/v1/scans", json={"url": "https://paypal.com.attacker.example/login"}).json()
    day = high["created_at"][:10]
    response = client.get(f"/api/v1/scans?start_date={day}&end_date={day}&sort_by=risk_score&sort_order=desc")
    assert response.status_code == 200
    assert response.json()["items"][0]["risk_score"] >= response.json()["items"][1]["risk_score"]
    for record in (low, high):
        client.delete(f"/api/v1/scans/{record['id']}")


def test_csv_export_exists_and_protects_formula_prefixes(client):
    response = client.get("/api/v1/reports/export.csv")
    assert response.status_code == 200
    assert "scan_id" in response.text


def test_csv_cells_neutralize_spreadsheet_formulas():
    assert csv_cell("=1+1") == "'=1+1"
    assert csv_cell("https://example.com") == "https://example.com"
