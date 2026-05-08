"""SCIM 2.0 / IGA compatibility adapter.

Implements a standards-oriented SCIM client for:
- GET /scim/v2/Users
- GET /scim/v2/Groups
- pagination with startIndex/count
- SCIM filter strings
- bearer token auth
- user/group normalization for OPA/AuthZEN context
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class SCIMUser:
    id: str
    user_name: str
    active: bool | None = None
    display_name: str | None = None
    email: str | None = None
    department: str | None = None
    groups: list[str] = field(default_factory=list)
    entitlements: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SCIMGroup:
    id: str
    display_name: str
    members: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class SCIMClient:
    def __init__(self, base_url: str, token: str, timeout: float = 20):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/scim+json, application/json",
            "Content-Type": "application/scim+json",
        }

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}{path}",
                headers=self.headers,
                params=params,
            )
            response.raise_for_status()
            return response.json()

    async def paged(self, path: str, filter: str | None = None, count: int = 100) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        start_index = 1

        while True:
            params: dict[str, Any] = {"startIndex": start_index, "count": count}
            if filter:
                params["filter"] = filter

            page = await self._get(path, params=params)
            batch = page.get("Resources", [])
            resources.extend(batch)

            total = int(page.get("totalResults", len(resources)))
            items_per_page = int(page.get("itemsPerPage", len(batch) or count))
            start_index += items_per_page

            if not batch or len(resources) >= total:
                break

        return resources

    async def list_users(self, filter: str | None = None) -> list[SCIMUser]:
        return [self.normalize_user(item) for item in await self.paged("/Users", filter=filter)]

    async def list_groups(self, filter: str | None = None) -> list[SCIMGroup]:
        return [self.normalize_group(item) for item in await self.paged("/Groups", filter=filter)]

    async def get_user_by_username(self, user_name: str) -> SCIMUser | None:
        users = await self.list_users(filter=f'userName eq "{user_name}"')
        return users[0] if users else None

    @staticmethod
    def normalize_user(item: dict[str, Any]) -> SCIMUser:
        emails = item.get("emails", []) or []
        primary_email = next((email.get("value") for email in emails if email.get("primary")), None)
        if not primary_email and emails:
            primary_email = emails[0].get("value")

        enterprise = item.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", {})
        groups = [group.get("display") or group.get("value") for group in item.get("groups", [])]
        entitlements = [ent.get("value") for ent in item.get("entitlements", [])]

        return SCIMUser(
            id=str(item.get("id", "")),
            user_name=str(item.get("userName", "")),
            active=item.get("active"),
            display_name=item.get("displayName"),
            email=primary_email,
            department=item.get("department") or enterprise.get("department"),
            groups=[value for value in groups if value],
            entitlements=[value for value in entitlements if value],
            raw=item,
        )

    @staticmethod
    def normalize_group(item: dict[str, Any]) -> SCIMGroup:
        members = [member.get("value") for member in item.get("members", [])]
        return SCIMGroup(
            id=str(item.get("id", "")),
            display_name=str(item.get("displayName", "")),
            members=[value for value in members if value],
            raw=item,
        )
