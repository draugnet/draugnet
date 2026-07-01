"""Event-template instantiation engine (PRD §8.5, Phase 3).

Turns a validated event-template ``definition`` plus a reporter's submitted
``values`` into an in-memory PyMISP :class:`MISPEvent`, ready for Draugnet's
existing create pipeline (Redis token + enhancement/reporting modules +
alerting). This reimplements MISP's own instantiator in Python (decision D1);
behaviour-parity reference:
``/var/www/MISP7/app/Lib/Tools/EventTemplateInstantiator.php``.

Entry point::

    build_event(definition, values, optional) -> MISPEvent

``values`` is keyed by the template's element ``id`` s. For attribute/tag/
galaxy fields the value is a string or a list of strings (repeatable). For
``object_field`` elements it is a ``{relation: value}`` map, or a list of such
maps (repeatable). ``galaxy_field`` values are cluster *value* strings (e.g.
``"APT28"``); ``tag_field`` values are full machine tags (e.g. ``tlp:amber``).

The event is fully built in memory and validated **before** any MISP push, so
an invalid submission raises ``HTTPException(400)`` and no token is ever minted
(PRD B18 — transactional intent at the single-``add_event`` level).

Element-type scope grows commit-by-commit across Phase 3; ``file_field`` and the
``event_report`` *element* land in Phase 4 and are skipped here (the slim
``description`` metadata → event report in the hybrid block is unrelated and
handled in Phase 3).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from pymisp import MISPEvent, MISPObject

from utils import create_misp_event, add_optional_form_data
import template_data

logger = logging.getLogger('uvicorn.error')

# Element types that carry no reporter-submitted data (UI-only or resolved from
# other elements). They are never expected as keys in ``values``.
_NON_INTERACTIVE_TYPES = ("section", "text_block", "object_reference")


# ---------------------------------------------------------------------------
# Value-shape helpers (mirror EventTemplateInstantiator.php)
# ---------------------------------------------------------------------------

def _is_empty(value: Any) -> bool:
    """True for None, blank/whitespace strings, and empty/all-empty lists."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            return True
        return all(_is_empty(item) for item in value)
    if isinstance(value, dict):
        if not value:
            return True
        return all(_is_empty(v) for v in value.values())
    return False


def _scalar_instances(value: Any) -> List[Any]:
    """Normalise a scalar-or-list field value to a list of non-empty scalars."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if not _is_empty(item)]
    if _is_empty(value):
        return []
    return [value]


def _object_instances(value: Any) -> List[Dict[str, Any]]:
    """Normalise object_field input to a list of relation→value maps.

    Accepts a single instance map (``{"from": ...}``) or a list of such maps
    (repeatable). Non-map entries are dropped.
    """
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, dict)]
    return []


def _interactive_elements(definition: dict) -> Dict[str, dict]:
    """Return ``{id: element}`` for every data-carrying element in the template."""
    out: Dict[str, dict] = {}
    for el in definition.get("structure") or []:
        if not isinstance(el, dict):
            continue
        etype = el.get("type")
        eid = el.get("id")
        if not etype or eid is None:
            continue
        if etype in _NON_INTERACTIVE_TYPES:
            continue
        out[eid] = el
    return out


def _add_event_tag(event: MISPEvent, name: Optional[str], seen: set) -> None:
    """Add an event tag once, skipping blanks and duplicates."""
    if not name or name in seen:
        return
    event.add_tag(name)
    seen.add(name)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_user_input(definition: dict, values: dict) -> List[str]:
    """Return a list of human-readable validation errors (empty = valid).

    Grown across Phase 3: this scaffold enforces unknown-id rejection and
    mandatory-element presence; per-relation and restriction checks are added
    with the object_field / tag_field / galaxy_field commits.
    """
    errors: List[str] = []
    interactive = _interactive_elements(definition)

    # Reject ids that don't correspond to a data-carrying element — a stale or
    # buggy client shouldn't be able to inject arbitrary keys.
    for key in values.keys():
        if key not in interactive:
            errors.append(f'unknown field id in user input: {key}')

    # Mandatory elements must be present and non-empty.
    for eid, el in interactive.items():
        if el.get("mandatory") and (eid not in values or _is_empty(values[eid])):
            errors.append(f'mandatory field "{eid}" is empty')

    return errors


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------

def build_event(definition: dict, values: dict, optional: Optional[dict] = None) -> MISPEvent:
    """Build an in-memory MISPEvent from a template definition + reporter values.

    Raises ``HTTPException(400)`` if the submission fails validation, before any
    MISP interaction.
    """
    if not isinstance(values, dict):
        raise HTTPException(status_code=400, detail="'values' must be an object keyed by element id.")
    optional = optional if isinstance(optional, dict) else {}

    errors = validate_user_input(definition, values)
    if errors:
        raise HTTPException(status_code=400, detail={"message": "User input is invalid.", "errors": errors})

    warnings: List[str] = []

    # Baseline event carries Draugnet's identity (source:draugnet tag) and the
    # default distribution/analysis/threat that event_defaults may override.
    event = create_misp_event()

    if warnings:
        for w in warnings:
            logger.warning("template instantiation: %s", w)

    return event
