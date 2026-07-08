"""Event-template loader for the two config-selected sources (PRD B8-B10).

A single source is active at a time (``template_config["source"]``):

* ``filesystem`` — walk ``template_config["dir"]`` for ``<name>/definition.json``
  and top-level ``*.json`` files, one level deep. Path-traversal-safe; every
  definition is schema-validated and invalid ones are skipped (listing) or
  reported as 422 (direct fetch). A ``draugnet_config["event_templates"]``
  whitelist (by uuid or name) may restrict which are exposed.

* ``misp`` — pull the exposed-only listing from the connected MISP
  (``GET /event_templates/exposed``, the Phase-1 contract) using the service key
  in ``misp_config``; each row's ``definition`` is re-validated defensively
  (A3). Results are cached for ``template_config["cache_ttl"]`` seconds.

Templates are addressed by their definition ``uuid`` (not file name), so
``get_template(uuid)`` resolves against the scanned/pulled set and never builds a
path from caller input.
"""
from __future__ import annotations

import os
import re
import json
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

import jsonschema
import httpx

logger = logging.getLogger('uvicorn.error')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(BASE_DIR, "schemas", "event-template-v1.schema.json")

_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

_validator: Optional[jsonschema.Draft7Validator] = None
_misp_cache: Dict[str, Any] = {"ts": 0.0, "definitions": []}


class TemplateNotFound(Exception):
    """Requested template uuid is not present in the active source."""


class TemplateInvalid(Exception):
    """Requested template exists but fails schema validation."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _get_validator() -> jsonschema.Draft7Validator:
    global _validator
    if _validator is None:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = json.load(f)
        _validator = jsonschema.Draft7Validator(schema)
    return _validator


def is_valid_uuid(value: str) -> bool:
    return bool(value) and _UUID_RE.match(value) is not None


def validate_definition(definition: Any) -> Tuple[bool, Optional[str]]:
    """Validate a definition against the bundled event-template-v1 schema.

    Returns ``(True, None)`` or ``(False, "<concise reason>")``.
    """
    try:
        _get_validator().validate(definition)
        return True, None
    except jsonschema.ValidationError as e:
        loc = "/".join(str(p) for p in e.absolute_path)
        reason = e.message + (f" (at {loc})" if loc else "")
        return False, reason
    except Exception as e:  # unreadable schema, non-dict input, ...
        return False, str(e)


# ---------------------------------------------------------------------------
# Config accessors (defensive: an older settings.py may lack the new keys)
# ---------------------------------------------------------------------------

def _template_config() -> dict:
    try:
        from config.settings import template_config
    except Exception:
        template_config = {}
    cfg = dict(template_config or {})
    cfg.setdefault("source", "filesystem")
    cfg.setdefault("dir", "event-templates")
    cfg.setdefault("cache_ttl", 300)
    return cfg


def template_source() -> str:
    return "misp" if _template_config().get("source") == "misp" else "filesystem"


def _template_dir() -> str:
    d = _template_config().get("dir", "event-templates")
    if not os.path.isabs(d):
        d = os.path.join(BASE_DIR, d)
    return d


def _event_template_whitelist() -> Optional[list]:
    try:
        from config.settings import draugnet_config
    except Exception:
        return None
    wl = (draugnet_config or {}).get("event_templates")
    return list(wl) if wl else None


def _passes_whitelist(definition: dict, whitelist: Optional[list]) -> bool:
    if not whitelist:
        return True
    return definition.get("uuid") in whitelist or definition.get("name") in whitelist


def _summary(definition: dict) -> dict:
    """The list view of a template (PRD B8)."""
    lib = definition.get("library_metadata") or {}
    return {
        "uuid": definition.get("uuid"),
        "name": definition.get("name"),
        "description": definition.get("description"),
        "tags": lib.get("tags") or [],
    }


def _summaries(definitions: List[dict], whitelist: Optional[list]) -> List[dict]:
    """Validate, whitelist-filter and dedupe definitions into list summaries."""
    out: List[dict] = []
    seen: set = set()
    for definition in definitions:
        if not isinstance(definition, dict):
            continue
        ok, reason = validate_definition(definition)
        if not ok:
            logger.warning("Skipping invalid event template: %s", reason)
            continue
        if not _passes_whitelist(definition, whitelist):
            continue
        uuid = definition.get("uuid")
        if uuid in seen:
            continue
        seen.add(uuid)
        out.append(_summary(definition))
    return out


# ---------------------------------------------------------------------------
# Filesystem source
# ---------------------------------------------------------------------------

def _iter_filesystem_definitions() -> List[Tuple[str, dict]]:
    """Return ``(path, definition)`` for every readable JSON definition in the
    template dir. Scans ``<dir>/<name>/definition.json`` and ``<dir>/*.json``
    one level deep; unreadable files are skipped with a log line."""
    tdir = _template_dir()
    results: List[Tuple[str, dict]] = []
    if not os.path.isdir(tdir):
        logger.warning("Event-template dir does not exist: %s", tdir)
        return results
    real_tdir = os.path.realpath(tdir)
    for entry in sorted(os.listdir(tdir)):
        full = os.path.join(tdir, entry)
        candidate: Optional[str] = None
        if os.path.isdir(full):
            cand = os.path.join(full, "definition.json")
            if os.path.isfile(cand):
                candidate = cand
        elif os.path.isfile(full) and entry.endswith(".json"):
            candidate = full
        if not candidate:
            continue
        # Defence in depth: the resolved file must stay within the template dir.
        if not os.path.realpath(candidate).startswith(real_tdir + os.sep):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                definition = json.load(f)
        except Exception as e:
            logger.warning("Skipping unreadable event template '%s': %s", candidate, e)
            continue
        if isinstance(definition, dict):
            results.append((candidate, definition))
    return results


def _list_filesystem() -> List[dict]:
    whitelist = _event_template_whitelist()
    return _summaries([d for _, d in _iter_filesystem_definitions()], whitelist)


def _get_filesystem(uuid: str) -> dict:
    whitelist = _event_template_whitelist()
    for _, definition in _iter_filesystem_definitions():
        if definition.get("uuid") != uuid:
            continue
        if not _passes_whitelist(definition, whitelist):
            continue
        ok, reason = validate_definition(definition)
        if not ok:
            raise TemplateInvalid(reason or "definition failed schema validation")
        return definition
    raise TemplateNotFound(uuid)


# ---------------------------------------------------------------------------
# MISP-pull source
# ---------------------------------------------------------------------------

def _extract_definition(row: Any) -> Optional[dict]:
    if not isinstance(row, dict):
        return None
    et = row.get("EventTemplate") if isinstance(row.get("EventTemplate"), dict) else row
    definition = et.get("definition")
    if isinstance(definition, str):
        try:
            definition = json.loads(definition)
        except Exception:
            return None
    return definition if isinstance(definition, dict) else None


async def _fetch_misp_definitions() -> List[dict]:
    cfg = _template_config()
    ttl = cfg.get("cache_ttl", 300) or 0
    now = time.monotonic()
    if ttl and _misp_cache["definitions"] and (now - _misp_cache["ts"]) < ttl:
        return _misp_cache["definitions"]

    try:
        from config.settings import misp_config
    except Exception:
        logger.error("template source 'misp' selected but misp_config is unavailable")
        return _misp_cache["definitions"]

    url = misp_config["url"].rstrip("/") + "/event_templates/exposed"
    headers = {
        "Authorization": misp_config["key"],
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(verify=misp_config.get("verifycert", True), timeout=30) as client:
            resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        rows = resp.json()
    except Exception as e:
        logger.error("Failed to pull exposed event templates from MISP: %s", e)
        # Serve the last good result (possibly empty) rather than erroring the endpoint.
        return _misp_cache["definitions"]

    definitions: List[dict] = []
    for row in rows or []:
        definition = _extract_definition(row)
        if definition is not None:
            definitions.append(definition)
    _misp_cache["definitions"] = definitions
    _misp_cache["ts"] = now
    return definitions


# ---------------------------------------------------------------------------
# Public API (source-agnostic)
# ---------------------------------------------------------------------------

async def list_templates() -> List[dict]:
    """List available templates for the active source as ``{uuid, name,
    description, tags}`` summaries; invalid definitions are excluded."""
    if template_source() == "misp":
        # MISP curates exposure server-side; the local whitelist is filesystem-only (B4).
        return _summaries(await _fetch_misp_definitions(), whitelist=None)
    return _list_filesystem()


async def get_template(uuid: str) -> dict:
    """Return the full definition for ``uuid`` from the active source.

    Raises :class:`TemplateNotFound` (→ 404) or :class:`TemplateInvalid` (→ 422).
    """
    if not is_valid_uuid(uuid):
        raise TemplateNotFound(uuid)
    if template_source() == "misp":
        for definition in await _fetch_misp_definitions():
            if definition.get("uuid") == uuid:
                ok, reason = validate_definition(definition)
                if not ok:
                    raise TemplateInvalid(reason or "definition failed schema validation")
                return definition
        raise TemplateNotFound(uuid)
    return _get_filesystem(uuid)
