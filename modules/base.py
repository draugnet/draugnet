# modules/base.py
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional, Dict, List
from redis import Redis


class ReportingModule(ABC):
    """Common interface for reporting-type modules (e.g., RTIR)."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config or {}

    @abstractmethod
    async def create_item(self, *, context: str, redis: Redis, external_id: str, event: Any, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new report/ticket/record in the external system."""
        ...

    @abstractmethod
    async def update_item(self, *,  context: str, redis: Redis, token:str, event: Any, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Append content / update an existing record in the external system."""
        ...
