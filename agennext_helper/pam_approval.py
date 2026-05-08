"""Standard PAM / JIT approval adapter.

Implements a provider-neutral approval API pattern for:
- standard approval webhook/API brokers
- privileged access management gateways
- ITSM approval workflows

No provider-specific SDK logic is included.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class PAMDecision:
    approved: bool
    status: str
    approver: str | None = None
    ticket_id: str | None = None
    request_id: str | None = None
    reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class PAMApprovalRequest:
    actor: str
    action: str
    resource: str
    reason: str | None = None
    org: str | None = None
    session_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


class PAMApprovalClient:
    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        provider: str = "standard-webhook",
        timeout: float = 20,
        poll_interval: float = 3,
        approval_timeout: float = 300,
    ):
        self.base_url = base_url.rstrip("/")
        self.provider = provider
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.approval_timeout = approval_timeout
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def request_approval(self, request: PAMApprovalRequest) -> PAMDecision:
        create_payload = {
            "provider": self.provider,
            "actor": request.actor,
            "action": request.action,
            "resource": request.resource,
            "reason": request.reason,
            "org": request.org,
            "session_id": request.session_id,
            "context": request.context,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/approvals",
                headers=self.headers,
                json=create_payload,
            )
            response.raise_for_status()
            created = response.json()

        request_id = created.get("request_id") or created.get("id")
        status = str(created.get("status", "pending")).lower()

        if status in {"approved", "denied", "rejected", "expired"}:
            return self.normalize_decision(created, request_id=request_id)

        if not request_id:
            return PAMDecision(
                approved=False,
                status="error",
                reason="PAM provider did not return request_id",
                raw=created,
            )

        return await self.wait_for_decision(request_id)

    async def wait_for_decision(self, request_id: str) -> PAMDecision:
        deadline = time.time() + self.approval_timeout

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while time.time() < deadline:
                response = await client.get(
                    f"{self.base_url}/approvals/{request_id}",
                    headers=self.headers,
                )
                response.raise_for_status()
                body = response.json()
                decision = self.normalize_decision(body, request_id=request_id)

                if decision.status in {"approved", "denied", "rejected", "expired", "error"}:
                    return decision

                await asyncio.sleep(self.poll_interval)

        return PAMDecision(
            approved=False,
            status="timeout",
            request_id=request_id,
            reason="Approval timed out",
        )

    @staticmethod
    def normalize_decision(body: dict[str, Any], request_id: str | None = None) -> PAMDecision:
        status = str(body.get("status", "pending")).lower()
        approved = status == "approved" or bool(body.get("approved", False))

        return PAMDecision(
            approved=approved,
            status="approved" if approved else status,
            approver=body.get("approver") or body.get("approved_by"),
            ticket_id=body.get("ticket_id") or body.get("ticket") or body.get("change_id"),
            request_id=request_id or body.get("request_id") or body.get("id"),
            reason=body.get("reason") or body.get("message"),
            raw=body,
        )
