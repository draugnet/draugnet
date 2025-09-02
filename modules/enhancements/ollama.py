# modules/reporting/flowintel.py
from __future__ import annotations
from typing import Any, Dict, Optional, List
import httpx
import json
from redis import Redis
import logging
from config.settings import misp_config
from datetime import datetime
import asyncio
import os
import re
from config.settings import modules_config # type: ignore

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

DEFAULT_PROMPT = '''
        Produce a clear, concise executive summary of the submitted incident report received via an anonymous reporting form of a CERT.


        --- INPUT START ---
        {input}
        --- INPUT END ---
        "
        '''

DEFAULT_MISP_PROMPT = '''
        Produce a clear, concise executive summary of the submitted MISP report.


        --- INPUT START ---
        {input}
        --- INPUT END ---
        "
        '''

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


    def _post_ollama_chat(self, endpoint: str, payload: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
        url = endpoint.rstrip("/") + "/api/generate"
        with httpx.Client(timeout=timeout) as client:
            logger.info(f"Posting to Ollama at {url} with payload: {json.dumps(payload)}")
            r = client.post(url, json=payload)
            logger.debug(f"Ollama response status: {r.status_code} with message: {r.text}")
            r.raise_for_status()
            return r.json()
        
    def run(self, action_type: str, context: str, content: Any, **kwargs) -> str:
        from config.settings import modules_config

        cfg = modules_config.get("enhancements", {}).get("ollama", {})

        endpoint: str = cfg.get("url", "http://127.0.0.1:11434")
        model: str = cfg.get("model", "qwen3:30b")
        prompt_template: str = cfg.get("prompt", DEFAULT_PROMPT)
        timeout: int = int(cfg.get("timeout", 120))

        if not cfg.get("enabled", False):
            logger.error("Ollama module is disabled in config.")
            return str(content)

        logger.info(f"Context: {context}")
        content = self.context_massage(context, content)
        prompt = prompt_template.replace("{input}", content)

        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }

        resp = self._post_ollama_chat(endpoint, payload, timeout)

        # handle both /generate and /chat style responses
        message = resp.get("response", "")
        if isinstance(resp.get("message"), dict):
            message = resp["message"].get("content", "")

        message = self._strip_think(message)
        return message
        
    def context_massage(self, context:str, content:str):
        tags = []
        object_types = []
        attribute_types = []
        event_reports = []
        galaxy_clusters = []
        result = ""
        # loop through each child element and compile a summary. The order matters as ollama will truncate when we reach the context size, so let's get the important things on top
        if context == "misp":
            result = f"Submission info: {content["info"]}\n"
            for tag in content.get('Tag', []):
                tags.append(tag["name"])
            if tags:
                result += f"Tags: {', '.join(tags)}\n"
            for galaxy_cluster in content.get('GalaxyCluster', []):
                galaxy_clusters.append(galaxy_cluster["value"])
            if galaxy_clusters:
                result += f"Clusters: {', '.join(galaxy_clusters)}\n"
            for event_report in content.get('EventReport', []):
                if event_report.get("name"):
                    event_reports.append(event_report["name"])
                if event_report.get("description"):
                    event_reports.append(event_report["description"])
            if event_reports:
                result += f"Reports: {'; '.join(event_reports)}\n"
            for obj in content.get('Object', []):
                if obj.get("name"):
                    object_types.append(obj["name"])
            if object_types:
                result += f"Objects: {', '.join(object_types)}\n"
            for attributes in content.get('Attribute', []):
                attribute_types.append(attributes["type"])
            if attribute_types:
                result += f"Attributes: {', '.join(attribute_types)}\n"
            return result
        elif context == "freetext":
            return content
        else:
            return content
        
    def _strip_think(self, text: str) -> str:
        return re.sub(r"<think>.*?</think>\s*", "", text, flags=re.DOTALL | re.IGNORECASE)
        