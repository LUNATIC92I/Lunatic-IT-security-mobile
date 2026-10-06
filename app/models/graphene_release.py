"""GrapheneOS release and compatibility models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GrapheneRelease(BaseModel):
    codename: str
    model: str
    channel: str
    version: str = Field(description="Build number, e.g. 2026100200 (YYYYMMDDNN)")
    build_date: str = Field(description="Date encoded in the version (YYYY-MM-DD)")
    published_at: str | None = Field(default=None, description="Timestamp from the official metadata (UTC)")
    install_url: str
    signature_url: str
    allowed_signers_url: str
    size_bytes: int | None = None
    source: str


class CompatibilityCheck(BaseModel):
    id: str
    label: str
    status: str  # ok | warn | fail | info
    detail: str
    action: str | None = None


class CompatibilityResult(BaseModel):
    device_id: str
    serial_masked: str
    transport: str
    codename: str | None
    model: str | None
    compatible: bool
    ready_to_prepare: bool
    summary: str
    checks: list[CompatibilityCheck]
    release: GrapheneRelease | None = None
    catalog_date: str
