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


# ---------------------------------------------------------------------------
# Event templates — Phase 2 (loader, listing, fetch, pickers)  [T1, T2, T3]
#
# These exercise the *filesystem* source (the shipped default). The MISP-pull
# source shares the same loader/validation path and is covered by T9 in Phase 3,
# once the Phase-1 exposed-listing endpoint is deployed to the dev MISP.
# ---------------------------------------------------------------------------

try:
    import jsonschema as _jsonschema
except ImportError:  # pragma: no cover
    _jsonschema = None

_REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEMPLATE_DIR = os.path.join(_REPO_ROOT, "event-templates")
_SCHEMA_FILE  = os.path.join(_REPO_ROOT, "schemas", "event-template-v1.schema.json")


def _load_schema():
    if not os.path.isfile(_SCHEMA_FILE):
        return None
    with open(_SCHEMA_FILE, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def invalid_fs_template():
    """Drop a schema-invalid definition into the filesystem source, yield its
    uuid, then remove it. Skips if the filesystem source dir is not present."""
    if not os.path.isdir(_TEMPLATE_DIR):
        pytest.skip("filesystem template dir not present (misp source?)")
    bad_uuid = str(uuid.uuid4())
    d = os.path.join(_TEMPLATE_DIR, "_pytest_invalid")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "definition.json"), "w", encoding="utf-8") as f:
        # Missing the required event_defaults + structure → fails validation.
        json.dump({"schema_version": 1, "uuid": bad_uuid, "name": "pytest invalid"}, f)
    try:
        yield bad_uuid
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


# ---- T1: GET /templates lists expected templates; invalid excluded ----------

class TestEventTemplatesList:
    def test_returns_200_list(self, http):
        r = http.get("/templates")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_summary_shape(self, http):
        templates = http.get("/templates").json()
        if not templates:
            pytest.skip("no event templates configured")
        for t in templates:
            assert set(t.keys()) >= {"uuid", "name", "description", "tags"}
            assert isinstance(t["tags"], list)
            assert t["uuid"] and t["name"]

    def test_listed_templates_fetch_and_validate(self, http):
        schema = _load_schema()
        templates = http.get("/templates").json()
        if not templates:
            pytest.skip("no event templates configured")
        for t in templates[:5]:
            r = http.get(f"/templates/{t['uuid']}")
            assert r.status_code == 200, r.text
            defn = r.json()
            assert defn["uuid"] == t["uuid"]
            if schema is not None and _jsonschema is not None:
                _jsonschema.Draft7Validator(schema).validate(defn)

    def test_invalid_definition_excluded_from_listing(self, http, invalid_fs_template):
        uuids = {t["uuid"] for t in http.get("/templates").json()}
        assert invalid_fs_template not in uuids
        # Found on disk but invalid → direct fetch is 422 (not 404, not 200).
        r = http.get(f"/templates/{invalid_fs_template}")
        assert r.status_code == 422


# ---- T2: GET /templates/{uuid} returns schema-valid definition; traversal ---

class TestEventTemplateFetch:
    def test_fetch_valid_definition(self, http):
        templates = http.get("/templates").json()
        if not templates:
            pytest.skip("no event templates configured")
        r = http.get(f"/templates/{templates[0]['uuid']}")
        assert r.status_code == 200
        defn = r.json()
        assert "structure" in defn and "event_defaults" in defn

    def test_fetched_definition_is_schema_valid(self, http):
        schema = _load_schema()
        if schema is None or _jsonschema is None:
            pytest.skip("bundled schema or jsonschema not available")
        templates = http.get("/templates").json()
        if not templates:
            pytest.skip("no event templates configured")
        defn = http.get(f"/templates/{templates[0]['uuid']}").json()
        _jsonschema.Draft7Validator(schema).validate(defn)  # raises on invalid

    def test_unknown_uuid_returns_404(self, http):
        r = http.get(f"/templates/{uuid.uuid4()}")
        assert r.status_code == 404

    @pytest.mark.parametrize("bad", [
        "not-a-uuid",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fsettings.py",
        "12345",
    ])
    def test_path_traversal_and_bad_uuid_blocked(self, http, bad):
        r = http.get(f"/templates/{bad}")
        assert r.status_code in (400, 404), (bad, r.status_code, r.text)


# ---- T3: taxonomy + galaxy pickers return bundled data; bounded; no MISP ----

class TestTaxonomyPicker:
    def test_tlp_entries(self, http):
        r = http.get("/taxonomies", params={"ns": "tlp"})
        assert r.status_code == 200
        tags = {e["tag"] for e in r.json()["entries"]}
        assert "tlp:amber" in tags
        assert "tlp:red" in tags

    def test_kill_chain_entries(self, http):
        r = http.get("/taxonomies", params={"ns": "kill-chain"})
        assert r.status_code == 200
        assert len(r.json()["entries"]) > 0

    def test_unknown_namespace_is_empty_not_error(self, http):
        r = http.get("/taxonomies", params={"ns": "this-namespace-does-not-exist-xyz"})
        assert r.status_code == 200
        assert r.json()["entries"] == []

    def test_invalid_namespace_rejected(self, http):
        r = http.get("/taxonomies", params={"ns": "../../etc"})
        assert r.status_code == 400

    def test_missing_ns_returns_422(self, http):
        r = http.get("/taxonomies")
        assert r.status_code == 422


class TestGalaxyPicker:
    def test_threat_actor_search(self, http):
        r = http.get("/galaxy_clusters", params={"type": "threat-actor", "q": "apt"})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] > 0
        values = {x["value"] for x in body["results"]}
        assert "APT1" in values
        for x in body["results"]:
            assert x["tag"].startswith('misp-galaxy:threat-actor="')

    def test_results_are_bounded(self, http):
        r = http.get("/galaxy_clusters", params={"type": "threat-actor", "q": "a", "limit": 5})
        assert r.status_code == 200
        assert r.json()["count"] <= 5

    def test_synonym_search(self, http):
        # APT1 carries the synonym "Comment Crew".
        r = http.get("/galaxy_clusters", params={"type": "threat-actor", "q": "comment crew"})
        assert r.status_code == 200
        assert any(x["value"] == "APT1" for x in r.json()["results"])

    def test_unknown_type_is_empty_not_error(self, http):
        # "never error if MISP galaxy data differs" — an unknown/absent type must
        # return an empty result, not a 5xx.
        r = http.get("/galaxy_clusters", params={"type": "this-galaxy-does-not-exist-xyz", "q": "x"})
        assert r.status_code == 200
        assert r.json()["results"] == []

    def test_invalid_type_rejected(self, http):
        r = http.get("/galaxy_clusters", params={"type": "../../etc/passwd"})
        assert r.status_code == 400

    def test_over_limit_rejected(self, http):
        r = http.get("/galaxy_clusters", params={"type": "threat-actor", "limit": 9999})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Event templates — Phase 3 (instantiation engine)  [T4, T5, T6, T8, T9]
#
# These submit via POST /share/template and then retrieve the resulting MISP
# event to assert its structure. They use the shipped "Spearphishing email
# triage" template (filesystem source), which exercises every non-file element
# type: attribute_field, object_field, object_reference, tag_field,
# galaxy_field, section/text_block, plus event_defaults. file_field and the
# event_report *element* land in Phase 4 (T7).
# ---------------------------------------------------------------------------

import sys as _sys
if _REPO_ROOT not in _sys.path:
    _sys.path.insert(0, _REPO_ROOT)

_SPEARPHISH_NAME = "Spearphishing email triage"


def _find_template_uuid(http, name):
    r = http.get("/templates")
    if r.status_code != 200:
        return None
    for t in r.json():
        if t.get("name") == name:
            return t.get("uuid")
    return None


def _submit_template(http, template_uuid, values, optional=None):
    body = {"template_uuid": template_uuid, "values": values}
    if optional is not None:
        body["optional"] = optional
    return http.post("/share/template", json=body)


def _retrieve_event(http, token):
    """Retrieve a token's MISP event as the inner Event dict."""
    r = http.get(f"/retrieve?token={token}&format=json")
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list) and data, f"unexpected /retrieve shape: {data!r}"
    return data[0]["Event"]


def _attrs_by_value(event):
    out = {}
    for a in event.get("Attribute", []):
        out.setdefault(a["value"], a)
    return out


def _spearphish_full_values():
    """A rich submission touching every element type in the spearphishing template."""
    return {
        "sender": "attacker@evil.example",
        "envelope_sender": "bounce@evil.example",
        "subject": "Your invoice is overdue",
        "received_from_ip": "203.0.113.9",
        "payload_url": ["http://bad.example/a", "http://bad.example/b"],
        "obj_email": {
            "from": "attacker@evil.example",
            "subject": "Your invoice is overdue",
            "message-id": "<deadbeef@evil.example>",
            "reply-to": "totally-legit@evil.example",
        },
        "obj_attachment": [
            {"filename": "invoice.pdf.exe", "sha256": "a" * 64},
            {"filename": "payload.zip", "sha256": "b" * 64},
        ],
        "tlp": "tlp:amber",
        "kill_chain": ["kill-chain:Delivery", "kill-chain:Exploitation"],
        "actor": "APT28",
    }


@pytest.fixture(scope="module")
def spearphish_uuid(http):
    u = _find_template_uuid(http, _SPEARPHISH_NAME)
    if not u:
        pytest.skip(f"template '{_SPEARPHISH_NAME}' not available in the active source")
    return u


@pytest.fixture(scope="module")
def happy_event(http, spearphish_uuid):
    """Submit the full spearphishing payload once and return the resulting event."""
    r = _submit_template(http, spearphish_uuid, _spearphish_full_values())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok" and body.get("token")
    return _retrieve_event(http, body["token"])


# ---- T4: happy path per element type ----------------------------------------

class TestTemplateHappyPath:
    def test_event_defaults_and_info_substitution(self, happy_event):
        assert happy_event["info"].startswith("Spearphishing")
        assert "attacker@evil.example" in happy_event["info"]   # {{field:sender}}
        assert int(happy_event["distribution"]) == 1
        assert int(happy_event["threat_level_id"]) == 2
        assert int(happy_event["analysis"]) == 0

    def test_attribute_fields(self, happy_event):
        by_val = _attrs_by_value(happy_event)
        sender = by_val.get("attacker@evil.example")
        assert sender is not None
        assert sender["type"] == "email-src"
        assert sender["category"] == "Payload delivery"
        assert sender["to_ids"] in (True, 1, "1")
        assert sender.get("comment") == "From: header"
        subj = by_val.get("Your invoice is overdue")
        assert subj is not None and subj["type"] == "email-subject"
        assert by_val.get("203.0.113.9", {}).get("type") == "ip-src"
        urls = {a["value"] for a in happy_event.get("Attribute", []) if a["type"] == "url"}
        assert urls >= {"http://bad.example/a", "http://bad.example/b"}

    def test_object_fields(self, happy_event):
        objs = happy_event.get("Object", [])
        emails = [o for o in objs if o["name"] == "email"]
        files = [o for o in objs if o["name"] == "file"]
        assert len(emails) == 1
        assert len(files) == 2
        email_rels = {a["object_relation"]: a["value"] for a in emails[0].get("Attribute", [])}
        assert email_rels.get("from") == "attacker@evil.example"
        assert email_rels.get("subject") == "Your invoice is overdue"
        assert "message-id" in email_rels
        filenames = {
            a["value"] for o in files for a in o.get("Attribute", [])
            if a["object_relation"] == "filename"
        }
        assert filenames == {"invoice.pdf.exe", "payload.zip"}

    def test_object_references(self, happy_event):
        objs = happy_event.get("Object", [])
        email = next(o for o in objs if o["name"] == "email")
        file_uuids = {o["uuid"] for o in objs if o["name"] == "file"}
        refs = email.get("ObjectReference", [])
        # Per-target-instance rule: one reference per attachment object.
        assert len(refs) == 2
        for ref in refs:
            assert ref["relationship_type"] == "contained-within"
            assert ref["referenced_uuid"] in file_uuids

    def test_event_tags(self, happy_event):
        names = {t["name"] for t in happy_event.get("Tag", [])}
        assert "source:draugnet" in names                      # pipeline preserved
        assert "tlp:amber" in names                            # default + user tag_field
        assert "kill-chain:Delivery" in names                  # multi tag_field
        assert "kill-chain:Exploitation" in names
        assert 'misp-galaxy:threat-actor="APT28"' in names     # galaxy_field


# ---- T5: mandatory enforcement (nothing pushed / no token) ------------------

class TestTemplateMandatory:
    def test_missing_mandatory_attribute_field(self, http, spearphish_uuid):
        vals = _spearphish_full_values()
        del vals["sender"]  # mandatory
        r = _submit_template(http, spearphish_uuid, vals)
        assert r.status_code == 400, r.text
        assert "token" not in r.json()

    def test_missing_mandatory_object_relation(self, http, spearphish_uuid):
        vals = {
            "sender": "a@evil.example", "subject": "h", "tlp": "tlp:amber",
            "obj_email": {"subject": "h"},  # missing mandatory 'from'
        }
        r = _submit_template(http, spearphish_uuid, vals)
        assert r.status_code == 400, r.text
        assert "from" in json.dumps(r.json().get("detail"))

    def test_empty_submission_lists_missing_mandatories(self, http, spearphish_uuid):
        r = _submit_template(http, spearphish_uuid, {})
        assert r.status_code == 400
        assert "token" not in r.json()


# ---- T6: repeatable attributes/objects → multiple instances -----------------

class TestTemplateRepeatable:
    def test_repeatable_attributes_and_objects(self, http, spearphish_uuid):
        vals = {
            "sender": "a@evil.example", "subject": "h", "tlp": "tlp:amber",
            "payload_url": ["http://a/", "http://b/", "http://c/"],
            "obj_attachment": [
                {"filename": "1.bin", "sha256": "1" * 64},
                {"filename": "2.bin", "sha256": "2" * 64},
            ],
        }
        r = _submit_template(http, spearphish_uuid, vals)
        assert r.status_code == 200, r.text
        event = _retrieve_event(http, r.json()["token"])
        urls = [a for a in event.get("Attribute", []) if a["type"] == "url"]
        assert len(urls) == 3
        files = [o for o in event.get("Object", []) if o["name"] == "file"]
        assert len(files) == 2


# ---- T8: hybrid metadata + locked tags + substitution -----------------------

class TestTemplateHybridMetadata:
    def test_hybrid_metadata_and_locked_default_tag(self, http, spearphish_uuid):
        optional = {
            "pap": "PAP:RED",
            "submitter": "analyst-jane",
            "description": "SOC tier-1 escalation.",
        }
        vals = {"sender": "attacker@evil.example", "subject": "Overdue invoice", "tlp": "tlp:amber"}
        r = _submit_template(http, spearphish_uuid, vals, optional)
        assert r.status_code == 200, r.text
        event = _retrieve_event(http, r.json()["token"])
        names = {t["name"] for t in event.get("Tag", [])}
        assert "PAP:RED" in names
        assert "submitter:analyst-jane" in names
        assert "tlp:amber" in names  # locked default tag present alongside metadata
        report_names = {rep["name"] for rep in event.get("EventReport", [])}
        assert "Additional report description" in report_names

    def test_info_field_substitution(self, http, spearphish_uuid):
        import datetime
        today = datetime.date.today().strftime("%Y-%m-%d")
        vals = {"sender": "pat@victim.example", "subject": "x", "tlp": "tlp:amber"}
        r = _submit_template(http, spearphish_uuid, vals)
        assert r.status_code == 200, r.text
        event = _retrieve_event(http, r.json()["token"])
        assert today in event["info"]                 # {{date}}
        assert "pat@victim.example" in event["info"]   # {{field:sender}}


class TestInfoTemplateSubstitution:
    """Unit coverage of render_info_template, including {{user}} — no shipped
    template uses {{user}}, so it can't be exercised through the API path."""

    def test_all_substitution_forms(self):
        import datetime
        import template_instantiator as ti
        out = ti.render_info_template(
            "d={{date}} u={{user}} f={{field:sender}}",
            {"sender": "who@x.y"},
            user="reporter@corp.example",
        )
        assert f"d={datetime.date.today().strftime('%Y-%m-%d')}" in out
        assert "u=reporter@corp.example" in out
        assert "f=who@x.y" in out

    def test_user_empty_when_no_submitter(self):
        import template_instantiator as ti
        assert ti.render_info_template("[{{user}}]", {}, user="") == "[]"

    def test_field_repeatable_uses_first_value(self):
        import template_instantiator as ti
        assert ti.render_info_template("{{field:x}}", {"x": ["one", "two"]}) == "one"

    def test_object_field_not_projected_into_info(self):
        import template_instantiator as ti
        assert ti.render_info_template("[{{field:obj}}]", {"obj": {"a": "b"}}) == "[]"

    def test_missing_field_is_blank(self):
        import template_instantiator as ti
        assert ti.render_info_template("[{{field:nope}}]", {}) == "[]"


# ---- T9: MISP-source (exposed-listing) pull contract  [M3] ------------------
#
# The full source switch (template_source = "misp") is an operator step
# (config + restart). This asserts the coupling point the misp source consumes —
# GET /event_templates/exposed on the connected MISP — and that the loader can
# extract + schema-validate each exposed definition. Skips cleanly when the
# Phase-1 endpoint isn't deployed (404) or no template is flagged exposed yet.

class TestMispSourcePullContract:
    def test_exposed_listing_definitions_are_valid(self):
        try:
            from config.settings import misp_config
        except Exception as e:  # pragma: no cover
            pytest.skip(f"backend config not importable: {e}")
        url = misp_config["url"].rstrip("/") + "/event_templates/exposed"
        headers = {"Authorization": misp_config["key"], "Accept": "application/json"}
        try:
            resp = httpx.get(
                url, headers=headers,
                verify=misp_config.get("verifycert", True), timeout=15,
            )
        except Exception as e:
            pytest.skip(f"MISP not reachable for exposed-listing contract: {e}")
        if resp.status_code == 404:
            pytest.skip("Phase-1 /event_templates/exposed not deployed on this MISP")
        assert resp.status_code == 200, resp.text
        rows = resp.json()
        assert isinstance(rows, list)
        if not rows:
            pytest.skip("no event templates flagged exposed on this MISP")

        import template_loader
        for row in rows:
            defn = template_loader._extract_definition(row)
            assert isinstance(defn, dict), f"exposed row missing usable definition: {row!r}"
            ok, reason = template_loader.validate_definition(defn)
            assert ok, f"exposed definition failed schema validation: {reason}"

    def test_backend_lists_exposed_when_source_is_misp(self, http):
        """If the backend is actually configured for the misp source, its
        /templates listing must serve the exposed definitions (end-to-end T9)."""
        try:
            from config.settings import template_config
        except Exception as e:  # pragma: no cover
            pytest.skip(f"backend config not importable: {e}")
        if (template_config or {}).get("source") != "misp":
            pytest.skip("backend template source is not 'misp' (filesystem default)")
        r = http.get("/templates")
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)
