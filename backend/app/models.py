"""Pydantic models shared by the checks and the HTTP layer."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Status(StrEnum):
    """Outcome of a single check. INFO never affects the overall result."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"


class CheckResult(BaseModel):
    id: str
    title: str
    status: Status
    summary: str
    details: list[str] = Field(default_factory=list)
    records: list[str] = Field(default_factory=list)


class CheckRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253, examples=["example.com"])
    dkim_selectors: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Extra DKIM selectors to look up, for example 'selector1'.",
    )


class CheckResponse(BaseModel):
    domain: str
    overall: Status
    checks: list[CheckResult]
