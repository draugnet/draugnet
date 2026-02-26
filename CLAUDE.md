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

No formal test framework. Use the included shell script for manual API testing:

```bash
bash test.sh  # submits testevent.json to POST /share/misp
```

Or directly:
```bash
curl -X POST http://localhost:8999/share/misp -H 'Content-type: application/json' -d @testevent.json
```

Interactive API docs are available at `http://localhost:8999/docs`.

## Architecture

### Core Components

- **`main.py`** — FastAPI app with all API endpoints. Handles submission routes (`/share/misp`, `/share/raw`, `/share/objects`, `/share/stix`) and retrieval routes (`/retrieve`, `/timestamp`, `/object_templates`).
- **`utils.py`** — Shared utilities: MISP client wrapper, Redis token management, dynamic module loading/caching.
- **`config/settings.py`** — Runtime configuration for MISP, Redis, CORS, and all modules.

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
- The `misp-objects/` directory is a git submodule containing MISP object templates.
- CORS origins are controlled via `allowed_origins` in settings.
- The `draugnet_config.misp_object_templates` whitelist (empty = allow all) controls which MISP object templates users can submit via `/share/objects`.
