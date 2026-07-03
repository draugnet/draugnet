# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Abracadabra** is the backend API server for **Draugnet**, a lightweight community threat intelligence submission tool. It acts as a bridge between anonymous users and a MISP instance, enabling community cyber-threat information sharing without prior account negotiation. Users submit reports and receive a tracking token for follow-up.

## Running the Application

```bash
# Production
python main.py

# Development (hot reload)
fastapi dev main.py
```

Default port: **8999**. SSL is enabled if `ssl_cert_path`/`ssl_key_path` are set in `config/settings.py`.

## Setup

```bash
python3 -m venv ./venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/settings.default.py config/settings.py
# Edit config/settings.py with MISP URL/key, Redis, and optional module settings
```

`config/settings.py` is gitignored (contains credentials). `config/settings.default.py` is the template.

## Testing

Quick manual check — the included shell script submits `testevent.json` to `/share/misp`:

```bash
bash test.sh
# or directly:
curl -X POST http://localhost:8999/share/misp -H 'Content-type: application/json' -d @testevent.json
```

A **pytest** suite (`tests/test_api.py`) covers the API — including the full
event-template path (T1–T9) — by driving the live backend with httpx and
asserting the resulting MISP event structure. It is dev-only (`pytest` +
`httpx` are not in `requirements.txt`) and needs Redis + MISP up:

```bash
.venv/bin/python -m pytest tests/test_api.py
```

Interactive API docs are available at `http://localhost:8999/docs`.

## Architecture

### Core Components

- **`main.py`** — FastAPI app with all API endpoints. Handles submission routes (`/share/misp`, `/share/raw`, `/share/objects`, `/share/stix`, `/share/csv`, `/share/template`), retrieval routes (`/retrieve`, `/timestamp`, `/object_templates`), and event-template routes (`/templates`, `/templates/{uuid}`, `/taxonomies`, `/galaxy_clusters`).
- **`utils.py`** — Shared utilities: MISP client wrapper, Redis token management, dynamic module loading/caching.
- **`template_loader.py`** — Loads event-template definitions from the config-selected source (`filesystem` or `misp`), schema-validated against the bundled `schemas/event-template-v1.schema.json`. Backs `GET /templates{,/{uuid}}`.
- **`template_data.py`** — Bundled-data picker layer: taxonomy predicates/entries (`misp-taxonomies`) and lazy-loaded galaxy clusters (`misp-galaxy`). Backs `GET /taxonomies` and `GET /galaxy_clusters`. Never queries MISP live (privacy: an anonymous-facing form can't surface a CSIRT's private clusters).
- **`template_instantiator.py`** — The instantiation engine: `build_event(definition, values, optional) -> MISPEvent` turns a reporter's filled values + the template's `event_defaults` into a MISP event (attributes, objects, references, tags, galaxies, files, event report). Backs `POST /share/template`.
- **`config/settings.py`** — Runtime configuration for MISP, Redis, CORS, modules, and the event-template source (`template_config`). See `settings.default.py` for documented keys.

### Data Flow

```
User Submission → FastAPI endpoint → MISP event create/update
                                   → Token generated/stored in Redis
                                   → [Async] Enhancement modules (Ollama)
                                   → [Async] Reporting modules (RTIR, Flowintel)
                                   → Return token to user
```

### Module System

Modules live under `modules/` in two categories:

- **`modules/reporting/`** — Push new submissions to external systems (RTIR, Flowintel). Each module implements `create_item()` and `update_item()` from `modules/base.py`.
- **`modules/enhancements/`** — Enrich submissions before storage (Ollama LLM summarization). Each module implements `run()`.

### Adding a New Submission Endpoint

Follow the pattern of any existing `@app.post("/share/<type>")` route: parse body → extract `optional` metadata → validate input → create/update MISP event → apply `add_optional_form_data()` → generate/touch token → run module pipeline → return `{"token": ..., "event_uuid": ..., "status": "ok"}`. Register the new format in `GET /share` as well.

Modules are loaded dynamically via `importlib` in `utils.py` based on what's configured and enabled in `config/settings.py`. Adding a new module means creating a Python file in the appropriate subdirectory that subclasses the relevant base class, then enabling it in config.

### Event-Template Data Entry

A guided, template-driven submission path (in addition to the raw `/share/*`
formats). A CSIRT authors an `event-template-v1` JSON definition (a labelled,
help-annotated form + event-level defaults); a reporter fills the rendered form
in DraugnetUI and submits; Abracadabra instantiates the corresponding MISP event.
Instantiation is **reimplemented here in Python/PyMISP** (not proxied to MISP), so
it keeps Draugnet's token/module/alerting pipeline and works even where MISP's own
template instantiator isn't deployed.

**Template source (one at a time, config-selected in `template_config`):**

| `source` | Behaviour |
|----------|-----------|
| `filesystem` (default) | Walk `template_config["dir"]` for `<name>/definition.json` (one level deep); schema-validate each; skip invalid (log). A `draugnet_config["event_templates"]` whitelist (by uuid or name; empty = all) may restrict which are exposed. |
| `misp` | Pull the **exposed-only** listing from the connected MISP using the `misp_config` service key; re-validate each definition defensively; cache for `template_config["cache_ttl"]` seconds. |

Config keys (`template_config{source,dir,cache_ttl}`, `draugnet_config["event_templates"]`)
are documented inline in `config/settings.default.py`.

**MISP-source pull contract:** `GET /event_templates/exposed` (added in MISP7,
Phase 1). Returns every event template flagged `exposed = 1` **that the service
account can also read** under the normal ACL (own-org OR `distribution = 1`
community; exposing is an additive marker, not a privilege escalation). Each row
carries the full decoded `definition`. To expose a template for Draugnet: set its
`exposed` flag (builder toggle "Expose to Draugnet", or the REST add/edit) and
ensure the service account can see it (same org, or template `distribution = 1`).

**Bundled data (git submodules, never fetched live):** `misp-objects` (object
templates, reused by `/object_templates`), `misp-taxonomies` (tag pickers),
`misp-galaxy` (galaxy/cluster pickers). Populate with `git submodule update
--init --recursive`.

**Endpoints:**

| Endpoint | Purpose |
|----------|---------|
| `GET /templates` | List available templates for the active source: `{uuid, name, description, tags}`. |
| `GET /templates/{uuid}` | Full definition for form rendering (404 not-found / 422 schema-invalid; path-traversal-safe). |
| `GET /taxonomies?ns=<namespace>` | Bundled taxonomy entries for a `tag_field` (server-restricted to the namespace). |
| `GET /galaxy_clusters?type=<galaxy_type>&q=<query>&limit=` | Bundled, lazy-loaded, bounded cluster typeahead for a `galaxy_field`. |
| `POST /share/template` | Body `{template_uuid, values:{<element_id>: <value(s)>}, optional:{pap,submitter,description}}` → `{token, event_uuid, status:"ok"}`. Create-only. Registered in `GET /share`. |

**Values contract** (what `POST /share/template` expects per element type):
attribute/tag/galaxy fields = `str | list[str]` (list when `multiple`/`repeatable`);
**tag** value = the full machine tag (`tlp:amber`); **galaxy** value = the cluster
*value* string (`APT28`), resolved server-side to `misp-galaxy:<type>="<value>"`;
`object_field` = `{relation: value}` or a list of such maps (repeatable); `file_field`
= `{filename, data(base64)}` or a list; `event_report` = a Markdown string. Empty
non-mandatory elements are omitted. Server-side validation (`validate_user_input`)
rejects missing mandatories, malformed shapes, and bad base64 **before** any MISP
push, so no token is minted on invalid input.

Behaviour parity reference (Python port of MISP's mapping):
`/var/www/MISP7/app/Lib/Tools/EventTemplateInstantiator.php`.

**Tests:** `tests/test_api.py` (httpx vs the live backend, which pushes to live
MISP). The event-template tests cover T1–T9; run with
`.venv/bin/python -m pytest tests/test_api.py` (needs Redis + MISP up). Fixtures
that drop a `definition.json` on disk skip unless the filesystem source is active,
so the suite is clean under either source.

### Storage

- **MISP**: Primary store for all threat intelligence events/attributes.
- **Redis** (db 5 by default): Token→UUID mapping, per-module external IDs, update timestamps.
  - `tokens:{token}` → MISP event UUID
  - `tokens_update:{token}` → last update timestamp
  - `modules:{module_name}:token:{token}` → external system ID (e.g., RTIR ticket number)

### External Service Dependencies

| Service | Required | Purpose |
|---------|----------|---------|
| MISP | Yes | Event storage and retrieval |
| Redis | Yes | Token/state management |
| RTIR | No | Auto-create incident tickets |
| Flowintel | No | Auto-create case management entries |
| Ollama | No | LLM-based report summarization |

## Related Projects

The **[DraugnetUI](https://github.com/draugnet/draugnetUI)** frontend is a separate git repo with its own `CLAUDE.md`. It is a static vanilla-JS site with no build step; it calls this backend's API using a `baseurl` set in `webroot/config/config.json`.

## Key Patterns

- All FastAPI route handlers are `async`; MISP calls via `pymisp` are wrapped to avoid blocking.
- `misp-objects/`, `misp-taxonomies/` and `misp-galaxy/` are git submodules bundling MISP object templates, taxonomies and galaxies respectively. They back `/object_templates`, `/taxonomies` and `/galaxy_clusters` and are never fetched live (`git submodule update --init --recursive`).
- CORS origins are controlled via `allowed_origins` in settings.
- The `draugnet_config.misp_object_templates` whitelist (empty = allow all) controls which MISP object templates users can submit via `/share/objects`. The parallel `draugnet_config.event_templates` whitelist (by uuid or name; empty = all) restricts which filesystem-source event templates are exposed.
