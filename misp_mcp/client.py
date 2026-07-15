"""Async MISP API client. Mostly read (search/view/index); plus a gated
write path (add_attribute, attach_tag) used only by misp_submit_ioc. The
write calls require a write-capable MISP key (MISP "User" role); a
read-only key gets HTTP 403, surfaced by the tool as an actionable error.

TLP enforcement (verified against MISP 2.5.x): MISP does NOT hide
TLP:AMBER/RED events from a same-org key (its Read Only role blocks
writes, not visibility), and attributes/restSearch does not return
event-level tags at all. So when redaction is enabled this client fetches
each hit's event to read its top-level Tag array and enforces the boundary
itself. Fail-closed: an unfetchable or tag-less-unknown event counts as
restricted.
"""

import asyncio

import httpx

from .config import Config

TIMEOUT_SECONDS = 15
MAX_RESULTS = 50
MAX_CONNECTIONS = 10
MAX_RETRIES = 2  # retry only transient network errors, never 4xx/5xx
RETRY_BACKOFF_SECONDS = 0.5
RESTRICTED_TAG_PREFIXES = ("tlp:amber", "tlp:red")


class MispClient:
    def __init__(self, config: Config):
        self._config = config
        self.show_restricted = config.show_restricted
        self._client = httpx.AsyncClient(
            base_url=config.url,
            headers={
                "Authorization": config.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            verify=config.verify_tls,
            timeout=TIMEOUT_SECONDS,
            limits=httpx.Limits(max_connections=MAX_CONNECTIONS),
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Single HTTP entry point. Retries only transient network errors
        (connect failures, timeouts) with linear backoff; raises 4xx/5xx
        immediately since those won't fix themselves on retry."""
        last_exc: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await self._client.request(method, path, **kwargs)
                resp.raise_for_status()
                return resp
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _tag_names(container: dict) -> set[str]:
        """Lowercased tag names from an event dict, checking both shapes
        MISP uses (Tag on events/view, EventTag on some index responses)."""
        tags = container.get("Tag") or [
            et.get("Tag", {}) for et in container.get("EventTag", []) or []
        ]
        return {t.get("name", "").lower() for t in tags or [] if isinstance(t, dict)}

    @classmethod
    def is_restricted(cls, event: dict | None) -> bool:
        """True if the event carries a restricted TLP tag. Fails closed:
        an unknown or unfetchable event is treated as restricted."""
        if event is None:
            return True
        tags = cls._tag_names(event)
        return any(t.startswith(p) for t in tags for p in RESTRICTED_TAG_PREFIXES)

    async def get_event(self, event_id: str) -> dict | None:
        """Full event (metadata, Tag and Attribute arrays). None on failure."""
        if not event_id:
            return None
        try:
            resp = await self._request("GET", f"/events/view/{event_id}")
            body = resp.json()
            return body.get("Event") if isinstance(body, dict) else None
        except httpx.HTTPError:
            return None

    async def _events_by_id(self, event_ids: list[str]) -> dict[str, dict | None]:
        """Fetch several distinct events concurrently, keyed by id."""
        unique = [e for e in dict.fromkeys(event_ids) if e]
        results = await asyncio.gather(*(self.get_event(e) for e in unique))
        return dict(zip(unique, results))

    async def search_attributes(self, value: str, limit: int = 20) -> list[dict]:
        """restSearch by IOC value; each hit annotated with is_restricted
        from its parent event's tags (fetched concurrently, deduped)."""
        resp = await self._request(
            "POST", "/attributes/restSearch", json={"value": value, "limit": limit}
        )
        body = resp.json()
        response = body.get("response", {}) if isinstance(body, dict) else {}
        attributes = (response.get("Attribute") or [])[:limit]

        if self.show_restricted:
            # Access is governed by the caller's own MISP key; show whatever
            # it can see. Skip the per-event tag fetch entirely (1 request,
            # not 1+N).
            for attr in attributes:
                attr["is_restricted"] = False
            return attributes

        events = await self._events_by_id([a.get("event_id") for a in attributes])
        for attr in attributes:
            attr["is_restricted"] = self.is_restricted(events.get(attr.get("event_id")))
        return attributes

    async def search_events(
        self,
        keyword: str | None = None,
        tag: str | None = None,
        date_from: str | None = None,
        date_until: str | None = None,
        limit: int = 20,
    ) -> list[dict]:
        """Event metadata search via /events/index. Each event annotated
        with is_restricted (from index tags when present, otherwise by
        fetching the full event concurrently — fail-closed either way)."""
        body: dict = {}
        if keyword:
            body["searcheventinfo"] = keyword
        if tag:
            body["searchtag"] = tag
        if date_from:
            body["searchDatefrom"] = date_from
        if date_until:
            body["searchDateuntil"] = date_until
        resp = await self._request("POST", "/events/index", json=body)
        payload = resp.json()
        events = payload[:limit] if isinstance(payload, list) else []

        if self.show_restricted:
            for item in events:
                item["is_restricted"] = False
            return events

        # Events whose index entry has no tag info must be verified by
        # fetching the full event; do those fetches concurrently.
        needs_fetch = [
            str((item.get("Event", item)).get("id"))
            for item in events
            if not self._tag_names(item.get("Event", item))
        ]
        fetched = await self._events_by_id(needs_fetch)
        for item in events:
            event = item.get("Event", item)
            if self._tag_names(event):
                item["is_restricted"] = self.is_restricted(event)
            else:
                item["is_restricted"] = self.is_restricted(fetched.get(str(event.get("id"))))
        return events

    async def attributes_in_event(
        self, event_id: str, since_days: int | None = None, limit: int = 500
    ) -> list[dict]:
        """Attributes of one event via /attributes/restSearch, newest-changed
        first, each with comment + timestamp (used for submission review).
        since_days limits to attributes changed in the last N days."""
        body: dict = {"eventid": event_id, "limit": limit}
        if since_days:
            body["timestamp"] = f"{int(since_days)}d"
        resp = await self._request("POST", "/attributes/restSearch", json=body)
        payload = resp.json()
        response = payload.get("response", {}) if isinstance(payload, dict) else {}
        return (response.get("Attribute") or [])[:limit]

    async def feeds(self) -> list[dict]:
        resp = await self._request("GET", "/feeds/index")
        payload = resp.json()
        if not isinstance(payload, list):
            return []
        return [f.get("Feed", {}) for f in payload if isinstance(f, dict)]

    # --- knowledge base: galaxies, taxonomies, tags (instance metadata,
    # not event content, so no TLP redaction applies) ----------------------

    async def search_galaxy_clusters(self, value: str, limit: int = 20) -> list[dict]:
        """Search galaxy clusters (threat actors, malware, tools, ATT&CK
        techniques) by name / synonym / value via /galaxy_clusters/restSearch.
        Returns the GalaxyCluster dicts (tolerant to the list-or-wrapped
        response shapes MISP uses across versions)."""
        resp = await self._request(
            "POST", "/galaxy_clusters/restSearch",
            json={"value": value, "limit": limit},
        )
        body = resp.json()
        response = body.get("response") if isinstance(body, dict) else body
        if not isinstance(response, list):
            return []
        out: list[dict] = []
        for item in response[:limit]:
            if isinstance(item, dict):
                out.append(item.get("GalaxyCluster", item))
        return out

    async def galaxies(self) -> list[dict]:
        """List galaxy types (Threat Actor, Malware, ATT&CK, ...) via
        /galaxies/index."""
        resp = await self._request("GET", "/galaxies/index")
        payload = resp.json()
        if not isinstance(payload, list):
            return []
        return [g.get("Galaxy", g) for g in payload if isinstance(g, dict)]

    async def taxonomies(self) -> list[dict]:
        """List taxonomies (TLP, kill-chain, PAP, ...) via /taxonomies. Each
        item keeps its Taxonomy dict plus the tag counts MISP returns."""
        resp = await self._request("GET", "/taxonomies")
        payload = resp.json()
        if not isinstance(payload, list):
            return []
        return [t for t in payload if isinstance(t, dict)]

    async def taxonomy(self, taxonomy_id: str) -> dict | None:
        """One taxonomy with its predicate/value entries via
        /taxonomies/view/<id>. None on failure."""
        try:
            resp = await self._request("GET", f"/taxonomies/view/{taxonomy_id}")
        except httpx.HTTPError:
            return None
        body = resp.json()
        return body if isinstance(body, dict) else None

    async def tags(self) -> list[dict]:
        """All tag definitions via /tags (filtered client-side by the tool)."""
        resp = await self._request("GET", "/tags")
        body = resp.json()
        if isinstance(body, dict):
            return body.get("Tag") or []
        if isinstance(body, list):
            return [t.get("Tag", t) for t in body if isinstance(t, dict)]
        return []

    # --- direct object / attribute access ----------------------------------

    async def get_object(self, object_id: str) -> dict | None:
        """One MISP object (a group of related attributes) via
        /objects/view/<id>. None on failure."""
        try:
            resp = await self._request("GET", f"/objects/view/{object_id}")
        except httpx.HTTPError:
            return None
        body = resp.json()
        if not isinstance(body, dict):
            return None
        obj = body.get("Object")
        return obj if isinstance(obj, dict) else None

    async def get_attribute(self, attribute_id: str) -> dict | None:
        """One attribute via /attributes/view/<id>. None on failure."""
        try:
            resp = await self._request("GET", f"/attributes/view/{attribute_id}")
        except httpx.HTTPError:
            return None
        body = resp.json()
        if not isinstance(body, dict):
            return None
        attr = body.get("Attribute")
        return attr if isinstance(attr, dict) else None

    async def search_attributes_query(
        self, *, attr_type: str | None = None, category: str | None = None,
        tag: str | None = None, to_ids: bool | None = None,
        event_id: str | None = None, since_days: int | None = None,
        limit: int = 25, page: int = 1,
    ) -> list[dict]:
        """Attribute restSearch by structured filters (type/category/tag/
        to_ids/event/recency) rather than by IOC value. Each hit annotated
        with is_restricted from its parent event, same as search_attributes.
        page (1-based) with limit gives stable pagination for big instances."""
        body: dict = {"limit": limit, "page": max(1, int(page))}
        if attr_type:
            body["type"] = attr_type
        if category:
            body["category"] = category
        if tag:
            body["tags"] = tag
        if to_ids is not None:
            body["to_ids"] = to_ids
        if event_id:
            body["eventid"] = event_id
        if since_days:
            body["timestamp"] = f"{int(since_days)}d"
        resp = await self._request("POST", "/attributes/restSearch", json=body)
        payload = resp.json()
        response = payload.get("response", {}) if isinstance(payload, dict) else {}
        attrs = (response.get("Attribute") or [])[:limit]

        if self.show_restricted:
            for a in attrs:
                a["is_restricted"] = False
            return attrs
        events = await self._events_by_id([a.get("event_id") for a in attrs])
        for a in attrs:
            a["is_restricted"] = self.is_restricted(events.get(a.get("event_id")))
        return attrs

    async def version(self) -> dict:
        resp = await self._request("GET", "/servers/getVersion.json")
        body = resp.json()
        return body if isinstance(body, dict) else {}

    async def whoami(self) -> dict | None:
        """The user MISP attributes this key to: {"email", "org"}. Used to
        stamp submissions with a verified identity instead of trusting the
        self-asserted X-MISP-User header / reporter field. None on failure
        (never blocks a submission)."""
        try:
            resp = await self._request("GET", "/users/view/me.json")
            body = resp.json()
        except httpx.HTTPError:
            return None
        if not isinstance(body, dict):
            return None
        user = body.get("User") if isinstance(body.get("User"), dict) else {}
        org = body.get("Organisation") if isinstance(body.get("Organisation"), dict) else {}
        return {"email": user.get("email"), "org": org.get("name")}

    # --- warninglists + operational health ---------------------------------

    async def check_warninglists(self, values: list[str]) -> dict:
        """POST /warninglists/checkValue: for each value, the warninglists it
        matches (known-good / noise lists like public DNS, Alexa, bogons).
        A non-empty match is a strong false-positive signal. Returns the raw
        {value: [matches]} map (tolerant to list-or-dict match entries)."""
        resp = await self._request(
            "POST", "/warninglists/checkValue", json={"value": values}
        )
        body = resp.json()
        return body if isinstance(body, dict) else {}

    async def workers(self) -> dict:
        """GET /servers/getWorkers: background worker/queue health. Requires an
        admin key; a non-admin key gets 403 (surfaced as an actionable error)."""
        resp = await self._request("GET", "/servers/getWorkers")
        body = resp.json()
        return body if isinstance(body, dict) else {}

    async def jobs(self, limit: int = 50) -> list[dict]:
        """GET /jobs/index: recent background jobs (fetch/enrichment/correlation)
        with status and any error. Requires an admin key."""
        resp = await self._request("GET", "/jobs/index")
        payload = resp.json()
        if not isinstance(payload, list):
            return []
        return [j.get("Job", j) for j in payload if isinstance(j, dict)][:limit]

    # --- write path (verified against MISP 2.5.x) --------------------------
    # Requires a write-capable key (MISP "User" role). A read-only key gets
    # HTTP 403 here, surfaced as an actionable error. Attributes are added
    # directly (no proposal); only the security team holds write keys.

    async def add_attribute(
        self, event_id: str, value: str, attr_type: str, category: str,
        to_ids: bool, comment: str, last_seen: str | None = None,
    ) -> dict:
        """POST /attributes/add/<event_id>. Returns the created Attribute
        (with id + uuid). Tags are NOT accepted inline — attach separately."""
        attr: dict = {
            "value": value, "type": attr_type, "category": category,
            "to_ids": to_ids, "comment": comment,
        }
        if last_seen:
            attr["last_seen"] = last_seen
        resp = await self._request(
            "POST", f"/attributes/add/{event_id}", json={"Attribute": attr}
        )
        body = resp.json()
        return body.get("Attribute", {}) if isinstance(body, dict) else {}

    async def attach_tag(self, attribute_uuid: str, tag: str) -> bool:
        """POST /tags/attachTagToObject. Existing tags only (Tag Editor
        denied). Returns True if saved, False on any failure (best-effort;
        one bad tag must not fail the whole submission)."""
        try:
            resp = await self._request(
                "POST", "/tags/attachTagToObject",
                json={"uuid": attribute_uuid, "tag": tag},
            )
            body = resp.json()
            return bool(isinstance(body, dict) and body.get("success"))
        except httpx.HTTPError:
            return False
