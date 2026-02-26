"""
Draugnet API test suite.

Usage:
    # Run all tests (requires a live Draugnet instance + MISP + Redis)
    pytest tests/test_api.py -v

    # Point at a non-default URL
    DRAUGNET_URL=https://my-draugnet.example pytest tests/test_api.py -v

    # Run only the fast, infrastructure-free tests
    pytest tests/test_api.py -v -k "not live"

Configuration via environment variables:
    DRAUGNET_URL    Base URL of the Draugnet API   (default: http://localhost:8999)
    DRAUGNET_VERIFY SSL certificate verification   (default: true)
"""

import os
import uuid
import json
import time

import pytest
import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("DRAUGNET_URL", "http://localhost:8999").rstrip("/")
VERIFY   = os.environ.get("DRAUGNET_VERIFY", "true").lower() not in ("false", "0", "no")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def url(path: str) -> str:
    return f"{BASE_URL}{path}"


def client() -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, verify=VERIFY, timeout=30)


# Minimal valid MISP event payload
def minimal_misp_event() -> dict:
    return {
        "Event": {
            "info": "Draugnet test event",
            "distribution": 0,
            "analysis": 0,
            "threat_level_id": 4,
            "Attribute": [
                {
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": f"192.0.2.{uuid.uuid4().int % 254 + 1}",
                    "to_ids": False,
                }
            ],
        }
    }


# Minimal valid STIX 2.1 bundle
def minimal_stix_bundle() -> dict:
    bundle_id = str(uuid.uuid4())
    indicator_id = str(uuid.uuid4())
    return {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{indicator_id}",
                "name": "Test indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z",
                "indicator_types": ["malicious-activity"],
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
            }
        ],
    }


# Minimal valid CSV string
def minimal_csv(extra_rows: list[dict] | None = None) -> str:
    rows = [{"type": "ip-dst", "value": "10.0.0.1", "category": "Network activity", "comment": "test"}]
    if extra_rows:
        rows.extend(extra_rows)
    header = "type,value,category,first_seen,last_seen,comment"
    lines = [header]
    for r in rows:
        lines.append(",".join([
            f'"{r.get("type","")}"',
            f'"{r.get("value","")}"',
            f'"{r.get("category","")}"',
            f'"{r.get("first_seen","")}"',
            f'"{r.get("last_seen","")}"',
            f'"{r.get("comment","")}"',
        ]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def http():
    """Module-scoped HTTP client."""
    with client() as c:
        yield c


@pytest.fixture(scope="module")
def csv_token(http):
    """Create one CSV report and return its token for retrieval/update tests."""
    r = http.post("/share/csv", json={"csv": minimal_csv()})
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture(scope="module")
def misp_token(http):
    """Create one MISP event and return its token."""
    r = http.post("/share/misp", json=minimal_misp_event())
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture(scope="module")
def raw_token(http):
    """Create one freetext report and return its token."""
    r = http.post("/share/raw", json={"text": "203.0.113.5 is scanning port 22 on our honeypot."})
    assert r.status_code == 200, r.text
    return r.json()["token"]


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------

class TestRoot:
    def test_returns_200(self, http):
        r = http.get("/")
        assert r.status_code == 200

    def test_response_shape(self, http):
        data = http.get("/").json()
        assert "name" in data
        assert "description" in data
        assert "endpoints" in data

    def test_name_is_draugnet(self, http):
        assert http.get("/").json()["name"] == "Draugnet"


# ---------------------------------------------------------------------------
# GET /share
# ---------------------------------------------------------------------------

class TestShareFormats:
    def test_returns_200(self, http):
        assert http.get("/share").status_code == 200

    def test_all_formats_present(self, http):
        formats = http.get("/share").json().get("formats", {})
        assert set(formats.keys()) >= {"misp", "raw", "objects", "stix", "csv"}

    def test_each_format_has_url_and_method(self, http):
        for name, fmt in http.get("/share").json()["formats"].items():
            assert "url"    in fmt, f"{name} missing 'url'"
            assert "method" in fmt, f"{name} missing 'method'"


# ---------------------------------------------------------------------------
# POST /share/csv
# ---------------------------------------------------------------------------

class TestShareCSV:
    def test_create_success(self, http):
        r = http.post("/share/csv", json={"csv": minimal_csv()})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "token" in body
        assert "event_uuid" in body

    def test_missing_csv_field(self, http):
        r = http.post("/share/csv", json={})
        assert r.status_code == 400

    def test_empty_csv_body(self, http):
        r = http.post("/share/csv", json={"csv": ""})
        assert r.status_code == 400

    def test_csv_no_data_rows(self, http):
        r = http.post("/share/csv", json={"csv": "type,value,category"})
        assert r.status_code == 400

    def test_csv_missing_required_field_value(self, http):
        bad_csv = "type,value,category\nip-dst,,Network activity"
        r = http.post("/share/csv", json={"csv": bad_csv})
        assert r.status_code == 400

    def test_csv_missing_required_field_type(self, http):
        bad_csv = "type,value,category\n,10.0.0.1,Network activity"
        r = http.post("/share/csv", json={"csv": bad_csv})
        assert r.status_code == 400

    def test_csv_with_optional_metadata(self, http):
        r = http.post("/share/csv", json={
            "csv": minimal_csv(),
            "optional": {"title": "Pytest submission", "tlp": "tlp:green"},
        })
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_update_existing_event(self, http, csv_token):
        r = http.post(f"/share/csv?token={csv_token}", json={
            "csv": minimal_csv([{"type": "domain", "value": "evil.example.com"}])
        })
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_invalid_token_returns_404(self, http):
        r = http.post("/share/csv?token=nonexistent-token-xyz", json={"csv": minimal_csv()})
        assert r.status_code == 404

    def test_csv_multiple_rows(self, http):
        extra = [
            {"type": "domain",   "value": "example.net"},
            {"type": "url",      "value": "http://bad.example.org/path"},
            {"type": "md5",      "value": "d41d8cd98f00b204e9800998ecf8427e"},
        ]
        r = http.post("/share/csv", json={"csv": minimal_csv(extra)})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /share/misp
# ---------------------------------------------------------------------------

class TestShareMISP:
    def test_create_success(self, http):
        r = http.post("/share/misp", json=minimal_misp_event())
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "token" in body
        assert "event_uuid" in body

    def test_missing_body_raises_error(self, http):
        r = http.post("/share/misp", content=b"{}")
        # empty event should fail with 4xx or 5xx — not 200
        assert r.status_code != 200

    def test_update_existing_event(self, http, misp_token):
        r = http.post(f"/share/misp?token={misp_token}", json=minimal_misp_event())
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_invalid_token_returns_404(self, http):
        r = http.post("/share/misp?token=bogus-token", json=minimal_misp_event())
        assert r.status_code == 404

    def test_event_wrapped_in_event_key(self, http):
        """Payload wrapped in {"event": {...}} is also accepted."""
        payload = {"event": minimal_misp_event()["Event"]}
        r = http.post("/share/misp", json=payload)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# POST /share/raw
# ---------------------------------------------------------------------------

class TestShareRaw:
    def test_create_success(self, http):
        r = http.post("/share/raw", json={"text": "198.51.100.42 phishing domain: evil.example.com"})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "token" in body

    def test_missing_text_field(self, http):
        r = http.post("/share/raw", json={})
        assert r.status_code == 400

    def test_empty_text_field(self, http):
        r = http.post("/share/raw", json={"text": ""})
        assert r.status_code == 400

    def test_update_existing_event(self, http, raw_token):
        r = http.post(f"/share/raw?token={raw_token}", json={"text": "Additional context: 203.0.113.99"})
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_invalid_token_returns_404(self, http):
        r = http.post("/share/raw?token=bogus-token", json={"text": "some text"})
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /share/stix
# ---------------------------------------------------------------------------

class TestShareSTIX:
    def test_create_success(self, http):
        r = http.post("/share/stix", json={"stix": minimal_stix_bundle()})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "token" in body
        assert "event_uuid" in body

    def test_missing_stix_field(self, http):
        r = http.post("/share/stix", json={})
        assert r.status_code == 400

    def test_stix_without_bundle_id(self, http):
        bad_bundle = {"type": "bundle", "objects": []}
        r = http.post("/share/stix", json={"stix": bad_bundle})
        assert r.status_code == 400

    def test_stix_as_json_string(self, http):
        """STIX payload may also be passed as a JSON string."""
        bundle = minimal_stix_bundle()
        r = http.post("/share/stix", json={"stix": json.dumps(bundle)})
        assert r.status_code == 200

    def test_invalid_json_string_returns_400(self, http):
        r = http.post("/share/stix", json={"stix": "this is not json {"})
        assert r.status_code == 400

    def test_invalid_token_returns_404(self, http):
        r = http.post("/share/stix?token=bogus-token", json={"stix": minimal_stix_bundle()})
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /object_templates
# ---------------------------------------------------------------------------

class TestObjectTemplates:
    def test_returns_200(self, http):
        assert http.get("/object_templates").status_code == 200

    def test_returns_list(self, http):
        assert isinstance(http.get("/object_templates").json(), list)

    def test_invalid_template_name_rejected(self, http):
        r = http.get("/object_templates?template=../../etc/passwd")
        assert r.status_code == 400

    def test_nonexistent_template_returns_404(self, http):
        r = http.get("/object_templates?template=this-template-does-not-exist-xyz")
        assert r.status_code == 404

    def test_template_name_with_spaces_rejected(self, http):
        r = http.get("/object_templates?template=bad name")
        assert r.status_code == 400

    def test_known_template_returns_definition(self, http):
        """If any template is installed, fetch the first one and validate shape."""
        templates = http.get("/object_templates").json()
        if not templates:
            pytest.skip("No object templates installed — skipping.")
        name = templates[0]
        r = http.get(f"/object_templates?template={name}")
        assert r.status_code == 200
        body = r.json()
        # MISP object definitions always have a 'name' and 'attributes' key
        assert "name"       in body
        assert "attributes" in body


# ---------------------------------------------------------------------------
# POST /share/objects
# ---------------------------------------------------------------------------

class TestShareObjects:
    def test_missing_template_name_returns_400(self, http):
        r = http.post("/share/objects", json={"data": {}})
        assert r.status_code == 400

    def test_with_valid_template(self, http):
        """Submit an object using the first available template (if any)."""
        templates = http.get("/object_templates").json()
        if not templates:
            pytest.skip("No object templates installed — skipping.")
        template_name = templates[0]
        # get template definition to pick a valid attribute
        defn = http.get(f"/object_templates?template={template_name}").json()
        attrs = defn.get("attributes", {})
        # Build a data dict with one attribute
        data = {}
        for attr_name, attr_meta in attrs.items():
            data[attr_name] = "test-value"
            break  # one attribute is enough
        r = http.post("/share/objects", json={"template_name": template_name, "data": data})
        # May fail with 500 if MISP rejects the attribute type/value combination,
        # but must not fail with a 4xx other than a MISP-level error
        assert r.status_code in (200, 500)

    def test_invalid_token_returns_404(self, http):
        templates = http.get("/object_templates").json()
        if not templates:
            pytest.skip("No object templates installed — skipping.")
        r = http.post(
            "/share/objects?token=bogus-token",
            json={"template_name": templates[0], "data": {}}
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /retrieve  (query-param version)
# ---------------------------------------------------------------------------

class TestRetrieveGET:
    def test_valid_token_default_json(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}")
        assert r.status_code == 200

    def test_valid_token_json_format(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}&format=json")
        assert r.status_code == 200
        # JSON format → response must be parseable JSON
        assert r.json() is not None

    def test_valid_token_csv_format(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}&format=csv")
        assert r.status_code == 200

    def test_valid_token_suricata_format(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}&format=suricata")
        assert r.status_code == 200

    def test_valid_token_text_format(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}&format=text")
        assert r.status_code == 200

    def test_valid_token_stix2_format(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}&format=stix2")
        assert r.status_code == 200

    def test_invalid_token_returns_404(self, http):
        r = http.get("/retrieve?token=completely-bogus-token")
        assert r.status_code == 404

    def test_missing_token_returns_error(self, http):
        # token defaults to None (Query(None, ...)), so FastAPI won't raise 422.
        # token_to_uuid(None) will either raise a TypeError (→ 500) or treat
        # "tokens:None" as an unknown key (→ 404). Either way, not a success.
        r = http.get("/retrieve")
        assert r.status_code >= 400

    def test_invalid_format_returns_422(self, http, csv_token):
        r = http.get(f"/retrieve?token={csv_token}&format=xml")
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# POST /retrieve  (body version)
# ---------------------------------------------------------------------------

class TestRetrievePOST:
    def test_valid_token_body(self, http, csv_token):
        r = http.post("/retrieve", json={"token": csv_token, "format": "json"})
        assert r.status_code == 200

    def test_missing_token_in_body(self, http):
        r = http.post("/retrieve", json={"format": "json"})
        assert r.status_code == 400

    def test_invalid_token_in_body(self, http):
        r = http.post("/retrieve", json={"token": "bogus-token"})
        assert r.status_code == 404

    def test_default_format_is_json(self, http, csv_token):
        r = http.post("/retrieve", json={"token": csv_token})
        assert r.status_code == 200
        assert r.json() is not None


# ---------------------------------------------------------------------------
# GET /timestamp
# ---------------------------------------------------------------------------

class TestTimestamp:
    def test_valid_token_returns_timestamp(self, http, csv_token):
        r = http.get(f"/timestamp?token={csv_token}")
        assert r.status_code == 200
        ts = int(r.text.strip())
        assert ts > 0

    def test_timestamp_is_recent(self, http, csv_token):
        r = http.get(f"/timestamp?token={csv_token}")
        ts = int(r.text.strip())
        now = int(time.time())
        assert abs(now - ts) < 3600, "Timestamp is more than 1 hour off — something is wrong."

    def test_invalid_token_returns_404(self, http):
        r = http.get("/timestamp?token=bogus-token")
        assert r.status_code == 404

    def test_timestamp_updates_after_modification(self, http, csv_token):
        ts_before = int(http.get(f"/timestamp?token={csv_token}").text.strip())
        time.sleep(1)
        http.post(f"/share/csv?token={csv_token}", json={
            "csv": minimal_csv([{"type": "domain", "value": "updated.example.com"}])
        })
        ts_after = int(http.get(f"/timestamp?token={csv_token}").text.strip())
        assert ts_after >= ts_before


# ---------------------------------------------------------------------------
# Body size limit (50 MB)
# ---------------------------------------------------------------------------

class TestBodySizeLimit:
    def test_oversized_body_returns_413(self, http):
        # Build a payload that exceeds 50 MB by inflating the text field
        big_text = "A" * (51 * 1024 * 1024)
        r = http.post(
            "/share/raw",
            content=json.dumps({"text": big_text}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 413


# ---------------------------------------------------------------------------
# Optional metadata fields  (shared across submission types)
# ---------------------------------------------------------------------------

class TestOptionalMetadata:
    """Verify the 'optional' block is accepted without error for each format."""

    OPTIONAL = {
        "title": "Pytest metadata test",
        "tlp": "tlp:amber",
        "pap": "PAP:GREEN",
        "description": "Automated test submission.",
        "submitter": "pytest-runner",
        "distribution": 0,
    }

    def test_csv_accepts_optional(self, http):
        r = http.post("/share/csv", json={"csv": minimal_csv(), "optional": self.OPTIONAL})
        assert r.status_code == 200

    def test_raw_accepts_optional(self, http):
        r = http.post("/share/raw", json={
            "text": "Test payload with metadata.",
            "optional": self.OPTIONAL,
        })
        assert r.status_code == 200

    def test_misp_accepts_optional(self, http):
        payload = minimal_misp_event()
        payload["optional"] = self.OPTIONAL
        r = http.post("/share/misp", json=payload)
        assert r.status_code == 200
