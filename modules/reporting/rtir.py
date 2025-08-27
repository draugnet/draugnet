# modules/reporting/rtir.py
from __future__ import annotations
from typing import Any, Dict, Optional, List
import httpx
from redis import Redis
import logging
from config.settings import misp_config

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

class Module:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.cfg = config or {}
        self.base_url = (self.cfg.get("url") or "").rstrip("/")
        self.verify = bool(self.cfg.get("verifycert", True))
        self.queue = self.cfg.get("queue", '')
        self.headers = {
            "Content-Type": "application/json",
            #"Authorization": f"token {self.cfg.get("auth_key", '')}",
        }
        self.misp_url = misp_config.get("url", "").rstrip("/")

    async def create_item(self, context: str, redis: Redis, token, event: str, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        submitter = "unknown"
        tags = []
        for tag in event.get("Tag", []):
            if tag.get("name", "").startswith("submitter:"):
                submitter = tag.get("name", "").split("submitter:")[-1]
            else:
                tags.append(tag.get("name", ""))
        event_reports = []
        for report in reports:
            event_reports.append(f"{report.get('name', '')}\n-------------------------------------------------\n\n{report.get('content', '')}")
        for report in event.get("EventReport", []):
            event_reports.append(f"{report.get('name', '')}\n-------------------------------------------------\n\n{report.get('content', '')}")
        
        logger.info(f"Creating RTIR ticket for event {event.get('uuid', '')}")
        url = f"{self.base_url}/REST/2.0/ticket?token={self.cfg.get("auth_key", '')}"
        subject = f"[{self.cfg.get("name", "Draugnet")}] {event.get("info", "Draugnet Report")}"
        content = f'''A new Draugnet report has been posted. Please check the MISP instance for more details.
        
        Submission type: {context}
        
        Submitted by: {submitter}

        MISP Event UUID: {event.get("uuid", "")}
        
        MISP URL: {self.misp_url}/events/view/{event.get("uuid", "")}

        Tags: {", ".join(tags) if tags else "None"}

        Reports: 

        =================================================
        {"\n\n=================================================\n\n ".join(event_reports) if tags else "None"}

        =================================================


        '''

        payload: Dict[str, Any] = {'Queue': self.queue, 'Subject': subject, 'Content': content}
    
        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            ticketId = str(data.get("id") or data.get("TicketId") or "")
            redis.set("modules:rtir:token:" + token, ticketId)
            redis.set("modules:rtir:external_id:" + ticketId, token)
            return True

    async def update_item(self, context: str, redis: Redis, external_id: str, event, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not external_id:
            return {"ok": False, "error": "Missing external_id"}
        url = f"{self.base_url}/REST/2.0/ticket/{str(external_id, 'utf-8')}/comment?token={self.cfg.get("auth_key", '')}"
        submitter = "unknown"
        tags = []
        for tag in event.get("Tag", []):
            if tag.get("name", "").startswith("submitter:"):
                submitter = tag.get("name", "").split("submitter:")[-1]
            else:
                tags.append(tag.get("name", ""))
        event_reports = []
        for report in reports:
            event_reports.append(f"{report.get('name', '')}\n-------------------------------------------------\n\n{report.get('content', '')}")
        for report in event.get("EventReport", []):
            event_reports.append(f"{report.get('name', '')}\n-------------------------------------------------\n\n{report.get('content', '')}")
        
        content = f'''The report has been updated via Draugnet:

        Submission type: {context}
        
        Submitted by: {submitter}

        MISP Event UUID: {event.get("uuid", "")}
        
        MISP URL: {self.misp_url}/events/view/{event.get("uuid", "")}

        Tags: {", ".join(tags) if tags else "None"}

        Reports: 

        =================================================
        {"\n\n=================================================\n\n ".join(event_reports) if tags else "None"}

        =================================================

        '''
        payload: Dict[str, Any] = {"Content": content, "ContentType": "text/plain"}

        async with httpx.AsyncClient(verify=self.verify, timeout=30) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            logger.info(f"RTIR update response: {resp.text}")
            resp.raise_for_status()
            data = resp.json()
            return {"ok": True, "external_id": external_id, "raw": data}


# ---- Optional function-based fallback (supported by the loader) ----
async def create_item(config: Dict[str, Any], *, subject: str, content: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return await Module(config).create_item(subject=subject, content=content, meta=meta)

async def update_item(config: Dict[str, Any], *, external_id: str, content: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return await Module(config).update_item(external_id=external_id, content=content, meta=meta)
