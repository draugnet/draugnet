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

Element-type scope grew commit-by-commit across Phases 3–4. ``file_field`` is
handled here (base64 → ``attachment`` / encrypted ``malware-sample``); the
``event_report`` *element* lands next in Phase 4. (The slim ``description``
metadata → event report in the hybrid block is unrelated and handled in Phase 3.)
"""
from __future__ import annotations

import re
import base64
import binascii
import logging
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from pymisp import MISPEvent, MISPObject

from utils import create_misp_event, add_optional_form_data
import template_data

logger = logging.getLogger('uvicorn.error')

# The four substitution forms permitted in event_defaults.info_template
# (PRD §7.1); the template grammar is guaranteed by the bundled schema, so by
# render time we can trust it.
_INFO_TEMPLATE_RE = re.compile(r'\{\{(date|now|user|field:([a-zA-Z_][a-zA-Z0-9_]*))\}\}')

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


def _file_instances(value: Any) -> List[Dict[str, Any]]:
    """Normalise file_field input to a list of ``{filename, data}`` maps.

    Accepts a single instance map or a list of them (repeatable). Mirrors
    ``EventTemplateInstantiator::normaliseFileInstances``; non-map entries drop.
    """
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, dict)]
    return []


def _is_valid_base64(data: str) -> bool:
    """True if ``data`` is a decodable base64 string (parity with PHP's
    ``base64_decode($data, true)`` strict check)."""
    if not isinstance(data, str) or data == "":
        return False
    try:
        base64.b64decode(data, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


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


def _seen_event_tags(event: MISPEvent) -> set:
    """Names of tags already on the event (e.g. source:draugnet)."""
    seen = set()
    for tag in (event.tags or []):
        name = getattr(tag, "name", None)
        if name:
            seen.add(name)
    return seen


def _allowed_taxonomy_tags(namespaces: List[str]) -> Optional[set]:
    """Set of permitted machine tags across the restricted namespaces, resolved
    from bundled misp-taxonomies. Returns ``None`` when the field declares no
    restriction (any tag accepted)."""
    if not namespaces:
        return None
    allowed: set = set()
    for ns in namespaces:
        for entry in template_data.taxonomy_entries(ns):
            allowed.add(entry["tag"])
    return allowed


def _resolve_galaxy_value(galaxy_types: List[str], value: str) -> Optional[str]:
    """Resolve a chosen cluster value against the first matching bundled galaxy
    type; returns its ``misp-galaxy:<type>="<value>"`` tag, or ``None`` if the
    value isn't present in bundled data."""
    for gtype in galaxy_types or []:
        resolved = template_data.resolve_galaxy_cluster(gtype, value)
        if resolved:
            return resolved["tag"]
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_user_input(definition: dict, values: dict) -> List[str]:
    """Return a list of human-readable validation errors (empty = valid).

    Enforces (PRD B17): unknown-id rejection; mandatory element and mandatory
    object-relation presence; value shape per element type; repeatable /
    single-select cardinality; and tag/galaxy selections staying within the
    declared restrictions and present in bundled data.
    """
    errors: List[str] = []
    interactive = _interactive_elements(definition)

    # Reject ids that don't correspond to a data-carrying element — a stale or
    # buggy client shouldn't be able to inject arbitrary keys.
    for key in values.keys():
        if key not in interactive:
            errors.append(f'unknown field id in user input: {key}')

    for eid, el in interactive.items():
        present = eid in values and not _is_empty(values[eid])

        # Mandatory elements must be present and non-empty.
        if el.get("mandatory") and not present:
            errors.append(f'mandatory field "{eid}" is empty')
            continue
        if not present:
            continue

        etype = el.get("type")

        # attribute_field: value must be a string or list of strings; a
        # non-repeatable field rejects multiple values.
        if etype == "attribute_field":
            raw = values[eid]
            if isinstance(raw, dict):
                errors.append(f'attribute_field "{eid}": expected a string or list of strings')
            elif isinstance(raw, list) and not el.get("repeatable") and len(_scalar_instances(raw)) > 1:
                errors.append(f'attribute_field "{eid}" is not repeatable but received multiple values')

        # object_field: value must be a relation→value map or a list of them; a
        # non-repeatable field rejects multiple instances; every relation flagged
        # mandatory must be filled in each submitted instance.
        elif etype == "object_field":
            raw = values[eid]
            if isinstance(raw, dict):
                instances = [raw]
            elif isinstance(raw, list):
                instances = raw
            else:
                errors.append(f'object_field "{eid}": expected a relation→value object or a list of them')
                instances = []
            non_empty = [i for i in instances if not _is_empty(i)]
            if not el.get("repeatable") and len(non_empty) > 1:
                errors.append(f'object_field "{eid}" is not repeatable but received {len(non_empty)} instances')
            mandatory_relations = [
                r.get("object_relation") for r in (el.get("relations") or [])
                if r.get("mandatory") and r.get("object_relation")
            ]
            for idx, instance in enumerate(instances, start=1):
                if _is_empty(instance):
                    continue
                if not isinstance(instance, dict):
                    errors.append(f'object_field "{eid}" instance {idx}: expected a relation→value object')
                    continue
                for rel in mandatory_relations:
                    if rel not in instance or _is_empty(instance.get(rel)):
                        errors.append(
                            f'object_field "{eid}" instance {idx}: mandatory relation "{rel}" is empty'
                        )

        # tag_field: selections must stay within restrict_taxonomies and be
        # present in bundled data; single-select fields reject multiple values.
        elif el.get("type") == "tag_field":
            selections = _scalar_instances(values[eid])
            if not el.get("multiple") and len(selections) > 1:
                errors.append(f'tag_field "{eid}" is single-select but received {len(selections)} values')
            allowed = _allowed_taxonomy_tags(el.get("restrict_taxonomies") or [])
            if allowed is not None:
                for name in selections:
                    if str(name) not in allowed:
                        errors.append(
                            f'tag_field "{eid}": "{name}" is not permitted by restrict_taxonomies '
                            f'or not present in bundled data'
                        )

        # galaxy_field: selections must resolve within restrict_galaxy_types
        # against bundled misp-galaxy; single-select fields reject multiples.
        elif el.get("type") == "galaxy_field":
            gtypes = el.get("restrict_galaxy_types") or []
            selections = _scalar_instances(values[eid])
            if not el.get("multiple") and len(selections) > 1:
                errors.append(f'galaxy_field "{eid}" is single-select but received {len(selections)} values')
            for value in selections:
                if _resolve_galaxy_value(gtypes, str(value)) is None:
                    errors.append(
                        f'galaxy_field "{eid}": cluster "{value}" not found in bundled data for {gtypes}'
                    )

        # file_field: each instance must be a {filename, data} map with a
        # non-empty filename and valid base64 data; a non-repeatable field
        # rejects multiple files. The `as` (attachment/malware-sample) choice is
        # the author's, not reporter-supplied, so it isn't validated here. A
        # non-empty value that isn't a file map (e.g. a stale text control) is
        # rejected outright rather than silently dropped.
        elif etype == "file_field":
            instances = _file_instances(values[eid])
            if not instances:
                errors.append(
                    f'file_field "{eid}": expected a {{filename, data}} object or a list of them'
                )
            if not el.get("repeatable") and len(instances) > 1:
                errors.append(
                    f'file_field "{eid}" is not repeatable but received {len(instances)} files'
                )
            for idx, inst in enumerate(instances, start=1):
                filename = inst.get("filename")
                if not isinstance(filename, str) or filename.strip() == "":
                    errors.append(f'file_field "{eid}" instance {idx}: missing or empty filename')
                    continue
                data = inst.get("data")
                if not isinstance(data, str) or data == "":
                    errors.append(f'file_field "{eid}" instance {idx}: missing base64 data')
                    continue
                if not _is_valid_base64(data):
                    errors.append(f'file_field "{eid}" instance {idx}: data is not valid base64')

    return errors


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------

def _build_attributes(event: MISPEvent, definition: dict, values: dict) -> None:
    """attribute_field → one MISPAttribute per submitted value.

    ``section`` and ``text_block`` carry no data (UI-only) and are ignored.
    ``default_value`` is a UI prefill only — an unfilled attribute_field creates
    nothing server-side (mirrors EventTemplateInstantiator::buildAttributes).
    """
    for el in definition.get("structure") or []:
        if not isinstance(el, dict) or el.get("type") != "attribute_field":
            continue
        eid = el.get("id")
        if eid is None or eid not in values or _is_empty(values[eid]):
            continue
        misp = el.get("misp") or {}
        atype = misp.get("type")
        category = misp.get("category")
        to_ids = bool(misp["to_ids_default"]) if "to_ids_default" in misp else True
        comment = misp.get("comment_template") or ""
        for value in _scalar_instances(values[eid]):
            event.add_attribute(
                atype, str(value),
                category=category, to_ids=to_ids, comment=comment, distribution=5,
            )


def _build_objects(event: MISPEvent, definition: dict, values: dict) -> Dict[str, List[MISPObject]]:
    """object_field → one MISPObject(name) per submitted instance.

    Relation values come from the submitted instance map; the element's
    relation-level ``default_value`` fills any relation the reporter left blank
    (``hidden`` relations aren't shown in the form but their defaults still
    apply). A relation value may itself be a list (multiple attributes for one
    relation). PyMISP resolves each relation's type/category from the bundled
    object template. Returns ``{element_id: [MISPObject, ...]}`` for
    object_reference resolution.
    """
    instances_by_id: Dict[str, List[MISPObject]] = {}
    for el in definition.get("structure") or []:
        if not isinstance(el, dict) or el.get("type") != "object_field":
            continue
        eid = el.get("id")
        if eid is None or eid not in values or _is_empty(values[eid]):
            continue
        oname = (el.get("object_template") or {}).get("name")
        default_map: Dict[str, Any] = {}
        for r in el.get("relations") or []:
            rel = r.get("object_relation")
            dv = r.get("default_value")
            if rel and dv not in (None, ""):
                default_map[rel] = dv

        built: List[MISPObject] = []
        for instance in _object_instances(values[eid]):
            merged = dict(default_map)
            for rel, rel_value in instance.items():
                if not _is_empty(rel_value):
                    merged[rel] = rel_value
            if not merged:
                continue
            try:
                misp_object = MISPObject(oname)
                for rel, rel_value in merged.items():
                    for value in _scalar_instances(rel_value):
                        misp_object.add_attribute(rel, value=str(value), distribution=5)
            except Exception as e:
                logger.error("Failed to build object '%s' for field '%s': %s", oname, eid, e)
                raise HTTPException(
                    status_code=400,
                    detail=f"Could not build object for field '{eid}': {e}",
                )
            event.add_object(misp_object)
            built.append(misp_object)
        instances_by_id[eid] = built
    return instances_by_id


def _build_object_references(
    definition: dict, object_instances: Dict[str, List[MISPObject]], warnings: List[str]
) -> None:
    """object_reference → add references once all objects exist.

    Repeatable-target rule (PRD B15): one reference per resulting *target*
    instance. The first instance of ``from`` is linked to every instance of
    ``to`` — so, e.g., one email object references each of several attachment
    objects. If either endpoint was left unfilled the reference is skipped with
    a warning (never a hard failure).
    """
    for el in definition.get("structure") or []:
        if not isinstance(el, dict) or el.get("type") != "object_reference":
            continue
        frm = el.get("from")
        to = el.get("to")
        rel_type = el.get("relationship_type")
        comment = el.get("comment") or ""
        if not frm or not to or not rel_type:
            continue
        from_objs = object_instances.get(frm) or []
        to_objs = object_instances.get(to) or []
        if not from_objs or not to_objs:
            warnings.append(
                f'object_reference "{el.get("id")}" skipped: '
                f'"{frm}" or "{to}" has no instantiated object'
            )
            continue
        source = from_objs[0]
        for target in to_objs:
            source.add_reference(target.uuid, rel_type, comment=comment)


def _build_field_tags(event: MISPEvent, definition: dict, values: dict, seen: set) -> None:
    """tag_field / galaxy_field reporter selections → event tags.

    Selections are already restriction- and bundled-presence-checked in
    validate_user_input; tag_field values are applied verbatim, galaxy_field
    values are resolved to their ``misp-galaxy:<type>="<value>"`` tag.
    """
    for el in definition.get("structure") or []:
        if not isinstance(el, dict):
            continue
        etype = el.get("type")
        eid = el.get("id")
        if eid is None or eid not in values or _is_empty(values[eid]):
            continue
        if etype == "tag_field":
            for name in _scalar_instances(values[eid]):
                _add_event_tag(event, str(name), seen)
        elif etype == "galaxy_field":
            gtypes = el.get("restrict_galaxy_types") or []
            for value in _scalar_instances(values[eid]):
                tag = _resolve_galaxy_value(gtypes, str(value))
                if tag:
                    _add_event_tag(event, tag, seen)


def _build_files(event: MISPEvent, definition: dict, values: dict) -> None:
    """file_field → one file attribute per submitted ``{filename, data}`` instance.

    The template author's ``as`` choice selects the attribute type (parity with
    ``EventTemplateInstantiator::buildAttributes``): ``malware-sample`` produces
    an encrypted, password-protected (``infected``) ZIP — PyMISP flags it
    ``encrypt`` and MISP's ``onDemandEncrypt`` hook does the zipping server-side
    on push — with ``to_ids`` on; anything else is a plain ``attachment`` with
    ``to_ids`` off. Both use category ``Payload delivery`` and event-inherited
    distribution. ``data`` is the raw file content base64-encoded on the client;
    PyMISP base64-decodes it back into the attribute's ``data`` BytesIO. Shape /
    base64 validity is enforced up-front in ``validate_user_input``.
    """
    for el in definition.get("structure") or []:
        if not isinstance(el, dict) or el.get("type") != "file_field":
            continue
        eid = el.get("id")
        if eid is None or eid not in values or _is_empty(values[eid]):
            continue
        as_kind = "malware-sample" if el.get("as") == "malware-sample" else "attachment"
        for inst in _file_instances(values[eid]):
            filename = inst.get("filename")
            data = inst.get("data")
            if not filename or not data:
                continue  # guarded by validate_user_input already
            try:
                event.add_attribute(
                    as_kind, str(filename),
                    category="Payload delivery",
                    to_ids=(as_kind == "malware-sample"),
                    comment="", distribution=5, data=str(data),
                )
            except Exception as e:
                logger.error("Failed to build %s attribute for field '%s': %s", as_kind, eid, e)
                raise HTTPException(
                    status_code=400,
                    detail=f"Could not build file attribute for field '{eid}': {e}",
                )


def _flatten_field_values(values: dict) -> Dict[str, Any]:
    """Project reporter values to what ``{{field:<id>}}`` can reference: scalar
    or list-of-scalar field values. object_field maps (dict / list-of-dict) have
    no scalar projection and are dropped (mirrors the MISP info renderer)."""
    flat: Dict[str, Any] = {}
    for key, value in values.items():
        if isinstance(value, dict):
            continue
        if isinstance(value, list):
            if value and not all(isinstance(item, (str, int, float)) or item is None for item in value):
                continue  # list of object maps
        flat[key] = value
    return flat


def render_info_template(template_str: Optional[str], values: dict, user: str = "") -> str:
    """Substitute ``{{date}}/{{now}}/{{user}}/{{field:<id>}}`` in an info_template
    (PRD §7.1, parity with EventTemplateInfoRenderer.php). ``{{user}}`` resolves
    to the reporter's ``submitter`` value or an empty string (A1)."""
    if not isinstance(template_str, str) or template_str == "":
        return ""
    flat = _flatten_field_values(values)

    def _sub(m: "re.Match") -> str:
        expr = m.group(1)
        if expr == "date":
            return date.today().strftime("%Y-%m-%d")
        if expr == "now":
            return datetime.now().astimezone().isoformat()
        if expr == "user":
            return user or ""
        field_id = m.group(2)
        if field_id is None or field_id not in flat:
            return ""
        val = flat[field_id]
        if val is None:
            return ""
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val)

    return _INFO_TEMPLATE_RE.sub(_sub, template_str)


def _apply_event_defaults(
    event: MISPEvent, defaults: dict, values: dict, optional: dict, seen_tags: set, warnings: List[str]
) -> None:
    """Apply the template's event_defaults onto the baseline event: substituted
    ``info``, distribution (with the A5 sharing-group fallback), threat level,
    analysis, locked/unlocked default tags, and default galaxy_clusters resolved
    through bundled data (A6 skip-with-warning)."""
    info_template = defaults.get("info_template")
    if isinstance(info_template, str) and info_template.strip():
        user = str(optional.get("submitter") or "").strip()
        rendered = render_info_template(info_template, values, user)
        if rendered.strip():
            event.info = rendered

    if defaults.get("distribution") is not None:
        dist = int(defaults["distribution"])
        if dist == 4:
            sg = defaults.get("sharing_group_id")
            if sg is not None and int(sg) >= 1:
                event.distribution = 4
                event.sharing_group_id = int(sg)
            else:
                # Sharing-group ids aren't portable across instances (A5).
                warnings.append(
                    "event_defaults.distribution is 4 but no resolvable sharing_group_id; "
                    "falling back to distribution 0"
                )
                event.distribution = 0
        else:
            event.distribution = dist

    if defaults.get("threat_level_id") is not None:
        event.threat_level_id = int(defaults["threat_level_id"])
    if defaults.get("analysis") is not None:
        event.analysis = int(defaults["analysis"])

    # Default tags (the UI locks the ones marked locked; server-side both are
    # applied identically).
    for tag in defaults.get("tags") or []:
        if isinstance(tag, dict):
            _add_event_tag(event, tag.get("name"), seen_tags)

    # Default galaxy clusters → misp-galaxy tags, resolved via bundled data only.
    for gc in defaults.get("galaxy_clusters") or []:
        if not isinstance(gc, dict):
            continue
        gtype = gc.get("galaxy_type")
        gvalue = gc.get("value")
        resolved = template_data.resolve_galaxy_cluster(gtype, gvalue) if gtype and gvalue else None
        if resolved:
            _add_event_tag(event, resolved["tag"], seen_tags)
        else:
            warnings.append(
                f'event_defaults galaxy cluster {gtype}="{gvalue}" not in bundled data; skipped'
            )


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
    seen_tags = _seen_event_tags(event)

    _apply_event_defaults(
        event, definition.get("event_defaults") or {}, values, optional, seen_tags, warnings
    )

    _build_attributes(event, definition, values)
    object_instances = _build_objects(event, definition, values)
    _build_object_references(definition, object_instances, warnings)
    _build_field_tags(event, definition, values, seen_tags)
    _build_files(event, definition, values)

    # Slim hybrid metadata (D5): the template owns info/distribution/threat/
    # analysis/tags/galaxies; the generic block contributes only PAP (tag),
    # submitter (submitter:<name> tag) and description (event report). Layered on
    # top via the existing helper so behaviour matches the other submit formats.
    slim = {}
    for key in ("pap", "submitter", "description"):
        value = optional.get(key)
        if value not in (None, "", [], "undefined"):
            slim[key] = value
    if slim:
        event = add_optional_form_data(event, slim)

    if warnings:
        for w in warnings:
            logger.warning("template instantiation: %s", w)

    return event
