"""Standards-oriented SIEM export adapter.

Supported provider-neutral patterns:
- JSONL ingestion
- HTTP webhook export
- syslog export
- batch event forwarding

No SIEM-vendor-specific exporter logic is included.
"""

from __future__ import annotations

import json
import logging
import socket
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SIEMExporter:
    def __init__(
        self,
        source_log: str,
        webhook_url: str | None = None,
        webhook_token: str | None = None,
        syslog_host: str | None = None,
        syslog_port: int = 514,
        timeout: float = 20,
    ):
        self.source_log = Path(source_log)
        self.webhook_url = webhook_url
        self.webhook_token = webhook_token
        self.syslog_host = syslog_host
        self.syslog_port = syslog_port
        self.timeout = timeout

    async def read_events(self) -> list[dict[str, Any]]:
        if not self.source_log.exists():
            return []

        events: list[dict[str, Any]] = []

        with self.source_log.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    events.append(json.loads(line))
                except Exception:
                    logger.exception("Failed to parse audit event")

        return events

    async def export_events(self) -> dict[str, Any]:
        events = await self.read_events()

        results = {
            "events": len(events),
            "webhook_exported": 0,
            "syslog_exported": 0,
        }

        if self.webhook_url:
            exported = await self.export_webhook(events)
            results["webhook_exported"] = exported

        if self.syslog_host:
            exported = self.export_syslog(events)
            results["syslog_exported"] = exported

        return results

    async def export_webhook(self, events: list[dict[str, Any]]) -> int:
        if not self.webhook_url:
            return 0

        headers = {"Content-Type": "application/json"}
        if self.webhook_token:
            headers["Authorization"] = f"Bearer {self.webhook_token}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.webhook_url,
                headers=headers,
                json={"events": events},
            )
            response.raise_for_status()

        return len(events)

    def export_syslog(self, events: list[dict[str, Any]]) -> int:
        if not self.syslog_host:
            return 0

        exported = 0

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for event in events:
                payload = json.dumps(event, ensure_ascii=False)
                sock.sendto(payload.encode("utf-8"), (self.syslog_host, self.syslog_port))
                exported += 1

        return exported
