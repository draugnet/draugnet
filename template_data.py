"""Bundled reference-data access layer for the event-template feature.

Reads taxonomy and galaxy picker data from the bundled ``misp-taxonomies`` and
``misp-galaxy`` submodules only — never live-fetched from MISP (PRD D6/S1), so an
anonymous-facing form can never surface a CSIRT's private or custom clusters.

Taxonomies (PRD B6):
    * ``taxonomy_entries(namespace)`` builds the selectable machine tags for a
      namespace, handling both predicate-only tags (``tlp:red``,
      ``kill-chain:Delivery``) and predicate+entry tags
      (``admiralty-scale:source-reliability="a"``).

Galaxies (PRD B7):
    * ``search_galaxy_clusters(type, q)`` lazy-loads only ``clusters/<type>.json``
      and typeahead-searches by value/synonym, bounded.
    * ``resolve_galaxy_cluster(type, value)`` resolves a chosen value to its
      ``misp-galaxy:<type>="<value>"`` tag (and uuid).

Cluster files carry an internal ``type`` that occasionally differs from the file
name (e.g. ``attck4fraud.json`` → ``financial-fraud``); the tag string is always
built from that authoritative internal ``type`` while loading stays keyed on the
requested file name (the ``restrict_galaxy_types`` value), matching the PRD's
lazy-load-by-name model.
"""
from __future__ import annotations

import os
import re
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger('uvicorn.error')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TAXONOMIES_DIR = os.path.join(BASE_DIR, "misp-taxonomies")
GALAXY_CLUSTERS_DIR = os.path.join(BASE_DIR, "misp-galaxy", "clusters")

# Taxonomy namespaces and galaxy cluster file names may contain upper/lower case,
# digits, dashes and underscores (e.g. "PAP", "csirt_case_classification",
# "branded_vulnerability"). Dots and separators are rejected — this alone blocks
# path traversal, and a realpath-containment check adds defence in depth.
_NAME_RE = re.compile(r'^[A-Za-z0-9_-]+$')

# Lazy-load caches (a None value marks a known-missing/invalid name so we don't
# re-hit the filesystem on every request).
_taxonomy_cache: Dict[str, Optional[dict]] = {}
_galaxy_cache: Dict[str, Optional[dict]] = {}


def is_safe_bundled_name(name: str) -> bool:
    """True if ``name`` is safe to use as a bundled-data path component."""
    return bool(name) and _NAME_RE.match(name) is not None


def _safe_path(base_dir: str, *parts: str) -> Optional[str]:
    """Join ``parts`` onto ``base_dir`` and confirm the result stays inside it."""
    candidate = os.path.join(base_dir, *parts)
    real = os.path.realpath(candidate)
    base_real = os.path.realpath(base_dir)
    if real == base_real or real.startswith(base_real + os.sep):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Taxonomies
# ---------------------------------------------------------------------------

def load_taxonomy(namespace: str) -> Optional[dict]:
    """Load and cache a taxonomy's ``machinetag.json`` (None if absent/invalid)."""
    if namespace in _taxonomy_cache:
        return _taxonomy_cache[namespace]
    if not is_safe_bundled_name(namespace):
        return None
    path = _safe_path(TAXONOMIES_DIR, namespace, "machinetag.json")
    data: Optional[dict] = None
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Failed to load taxonomy '%s': %s", namespace, e)
            data = None
    _taxonomy_cache[namespace] = data
    return data


def taxonomy_entries(namespace: str) -> List[Dict[str, Any]]:
    """Return the selectable machine tags for a taxonomy namespace.

    Each entry: ``{tag, predicate, value, label, description, numerical_value,
    colour}``. Empty list if the namespace is unknown or unreadable.
    """
    data = load_taxonomy(namespace)
    if not data:
        return []
    ns = data.get("namespace") or namespace
    entries_by_pred: Dict[str, list] = {}
    for block in data.get("values", []) or []:
        entries_by_pred[block.get("predicate")] = block.get("entry", []) or []

    out: List[Dict[str, Any]] = []
    for pred in data.get("predicates", []) or []:
        pv = pred.get("value")
        if pv is None:
            continue
        entries = entries_by_pred.get(pv)
        if entries:
            for e in entries:
                ev = e.get("value")
                if ev is None:
                    continue
                out.append({
                    "tag": f'{ns}:{pv}="{ev}"',
                    "predicate": pv,
                    "value": ev,
                    "label": e.get("expanded") or ev,
                    "description": e.get("description") or "",
                    "numerical_value": e.get("numerical_value"),
                    "colour": e.get("colour") or pred.get("colour"),
                })
        else:
            out.append({
                "tag": f"{ns}:{pv}",
                "predicate": pv,
                "value": None,
                "label": pred.get("expanded") or pv,
                "description": pred.get("description") or "",
                "numerical_value": pred.get("numerical_value"),
                "colour": pred.get("colour"),
            })
    return out


def resolve_taxonomy_tag(namespace: str, tag: str) -> Optional[Dict[str, Any]]:
    """Return the entry dict for ``tag`` if it is valid within ``namespace``."""
    for entry in taxonomy_entries(namespace):
        if entry["tag"] == tag:
            return entry
    return None


# ---------------------------------------------------------------------------
# Galaxies
# ---------------------------------------------------------------------------

def load_galaxy_clusters(galaxy_type: str) -> Optional[dict]:
    """Lazy-load and cache ``clusters/<galaxy_type>.json`` (None if absent)."""
    if galaxy_type in _galaxy_cache:
        return _galaxy_cache[galaxy_type]
    if not is_safe_bundled_name(galaxy_type):
        return None
    path = _safe_path(GALAXY_CLUSTERS_DIR, galaxy_type + ".json")
    data: Optional[dict] = None
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Failed to load galaxy cluster file '%s': %s", galaxy_type, e)
            data = None
    _galaxy_cache[galaxy_type] = data
    return data


def _galaxy_tag(data: dict, galaxy_type: str, value: str) -> str:
    # The tag uses the cluster file's authoritative internal type; fall back to
    # the requested name if the file omits it.
    t = data.get("type") or galaxy_type
    return f'misp-galaxy:{t}="{value}"'


def _cluster_to_result(data: dict, galaxy_type: str, cluster: dict) -> Dict[str, Any]:
    value = cluster.get("value")
    meta = cluster.get("meta") or {}
    return {
        "value": value,
        "tag": _galaxy_tag(data, galaxy_type, value),
        "uuid": cluster.get("uuid"),
        "description": cluster.get("description") or "",
        "synonyms": meta.get("synonyms") or [],
    }


def search_galaxy_clusters(galaxy_type: str, query: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    """Typeahead-search a galaxy's clusters by value/synonym, bounded by ``limit``.

    Ranking: exact value match, then value prefix, then value/synonym substring.
    An empty query returns the first ``limit`` clusters. Never touches MISP.
    """
    data = load_galaxy_clusters(galaxy_type)
    if not data:
        return []
    values = data.get("values", []) or []
    if limit < 0:
        limit = 0
    q = (query or "").strip().lower()
    if not q:
        return [_cluster_to_result(data, galaxy_type, c) for c in values[:limit]]

    exact: List[dict] = []
    prefix: List[dict] = []
    contains: List[dict] = []
    for c in values:
        vl = (c.get("value") or "").lower()
        if not vl:
            continue
        if vl == q:
            exact.append(c)
        elif vl.startswith(q):
            prefix.append(c)
        else:
            syns = [s.lower() for s in ((c.get("meta") or {}).get("synonyms") or []) if isinstance(s, str)]
            if q in vl or any(q in s for s in syns):
                contains.append(c)
    ranked = exact + prefix + contains
    return [_cluster_to_result(data, galaxy_type, c) for c in ranked[:limit]]


def resolve_galaxy_cluster(galaxy_type: str, value: str) -> Optional[Dict[str, Any]]:
    """Resolve a chosen cluster value (or synonym) to its tag + uuid; None if unknown."""
    data = load_galaxy_clusters(galaxy_type)
    if not data:
        return None
    values = data.get("values", []) or []
    for c in values:
        if c.get("value") == value:
            return _cluster_to_result(data, galaxy_type, c)
    for c in values:
        syns = (c.get("meta") or {}).get("synonyms") or []
        if value in syns:
            return _cluster_to_result(data, galaxy_type, c)
    return None
