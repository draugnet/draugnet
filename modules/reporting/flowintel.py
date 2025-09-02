# modules/reporting/flowintel.py
from __future__ import annotations
from typing import Any, Dict, Optional, List
import httpx
import json
from redis import Redis
import logging
from config.settings import misp_config
from datetime import datetime

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

class Module:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.cfg = config or {}
        self.base_url = (self.cfg.get("url") or "").rstrip("/")
        self.verify = bool(self.cfg.get("verifycert", True))
        self.headers = {
            "X-API-KEY": self.cfg.get("auth_key", ''),
            "Content-Type": "application/json"
        }
        self.misp_url = misp_config.get("url", "").rstrip("/")

    async def create_item(self, context: str, redis: Redis, token, event: str, reports: List[Dict[str, Any]], enhanced_text: Optional[str] = None) -> Dict[str, Any]:
        submitter = "unknown"
        tags = []
        for tag in event.get("Tag", []):
            if tag.get("name", "").startswith("submitter:"):
                submitter = tag.get("name", "").split("submitter:")[-1]
            else:
                name = tag.get("name", "")
                tag_parts = name.split(":")
                if tag_parts[0] == "PAP" or tag_parts[0] == "tlp":
                    tags.append(tag.get("name", ""))

        event_reports = []
        for report in reports:
            event_reports.append(f"{report.get('name', '')}\n-------------------------------------------------\n\n{report.get('content', '')}")
        for report in event.get("EventReport", []):
            event_reports.append(f"{report.get('name', '')}\n-------------------------------------------------\n\n{report.get('content', '')}")
        description = f'''A new Draugnet report has been posted. Please check the MISP instance for more details.

**Submission type**: {context}
        
**Submitted by**: {submitter}

**MISP Event UUID**: {event.get("uuid", "")}
        
**MISP URL**: {self.misp_url}/events/view/{event.get("uuid", "")}
        '''
        if enhanced_text:
            description += f"\n\n{enhanced_text}\n"
        subject = f"[{self.cfg.get("name", "Draugnet")}] {event.get("info", "Draugnet Report")}"
        notes = "\n=================================================\n\n ".join(event_reports)
        case = {
            'title': subject + datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'description': description,
            'is_private': False,
            'tags': tags,
            # "clusters": [],
        }
        
        logger.info(f"Creating Flowintel case for event {event.get('uuid', '')}")
        url = f"{self.base_url}/api/case/create"
        payload: Dict[str, Any] = case


        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            caseId = str(data.get("case_id"))
            redis.set("modules:flowintel:token:" + token, caseId)
            redis.set("modules:flowintel:external_id:" + caseId, token)
            # Add notes to the case
            if notes:
                note_url = f"{self.base_url}/api/case/{caseId}/modif_case_note"
                note_payload = {
                    'note': notes
                }
                note_resp = await client.post(note_url, headers=self.headers, json=note_payload)
                note_resp.raise_for_status()

    async def update_item(self, context: str, redis: Redis, external_id: str, event, reports: List[Dict[str, Any]], enhanced_text: Optional[str] = None) -> Dict[str, Any]:
        if not external_id:
            return {"ok": False, "error": "Missing external_id"}
        url = f"{self.base_url}/api/case/{str(external_id, 'utf-8')}/modif_case_note"
        submitter = "unknown"
        tags = []
        for tag in event.get("Tag", []):
            if tag.get("name", "").startswith("submitter:"):
                submitter = tag.get("name", "").split("submitter:")[-1]
            else:
                tags.append(tag.get("name", ""))
        event_reports = []
        for report in reports:
            event_reports.append(f"**{report.get('name', '')}**\n\n{report.get('content', '')}")
        for report in event.get("EventReport", []):
            event_reports.append(f"**{report.get('name', '')}**\n\n{report.get('content', '')}")
        
        content = f'''The report has been updated via Draugnet:

**Submission type**: {context}
        
**Submitted by**: {submitter}

**MISP Event UUID**: {event.get("uuid", "")}
        
**MISP URL**: {self.misp_url}/events/view/{event.get("uuid", "")}
        {f"\n{enhanced_text}\n" if enhanced_text else ""}
**Tags**: {", ".join(tags) if tags else "None"}

**Reports**: 

{"\n\n=================================================\n\n ".join(event_reports) if event_reports else "None"}

=================================================

        '''
        note_payload = {
            'note': content
        }

        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            resp = await client.post(url, headers=self.headers, json=note_payload)
            resp.raise_for_status()
            data = resp.json()
            return {"ok": True, "external_id": external_id, "raw": data}


# ---- Optional function-based fallback (supported by the loader) ----
async def create_item(config: Dict[str, Any], *, subject: str, content: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return await Module(config).create_item(subject=subject, content=content, meta=meta)

async def update_item(config: Dict[str, Any], *, external_id: str, content: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return await Module(config).update_item(external_id=external_id, content=content, meta=meta)
