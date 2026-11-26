from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

import cert_expiry as ce

NOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


class FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return self.pages


class FakeIot:
    def __init__(self, certs: dict[str, tuple[str, datetime]]) -> None:
        self.certs = certs

    def get_paginator(self, name: str) -> FakePaginator:
        assert name == "list_certificates"
        listed = [{"certificateId": cid, "certificateArn": f"arn:aws:iot:ap-south-1:1:cert/{cid}", "status": st} for cid, (st, _) in self.certs.items()]
        return FakePaginator([{"certificates": listed[:2]}, {"certificates": listed[2:]}])

    def describe_certificate(self, certificateId: str) -> dict[str, Any]:
        status, not_after = self.certs[certificateId]
        return {"certificateDescription": {"status": status, "validity": {"notBefore": NOW - timedelta(days=365), "notAfter": not_after}}}

    def list_principal_things(self, principal: str) -> dict[str, Any]:
        return {"things": [f"thing-{principal.rsplit('/', 1)[-1]}"]}


class FakeSns:
    def __init__(self) -> None:
        self.published: list[dict[str, Any]] = []

    def publish(self, **kwargs: Any) -> None:
        self.published.append(kwargs)


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch, env: pytest.MonkeyPatch):
    def install(certs: dict[str, tuple[str, datetime]]) -> FakeSns:
        sns = FakeSns()
        monkeypatch.setattr(ce, "_iot", lambda: FakeIot(certs))
        monkeypatch.setattr(ce, "_sns", lambda: sns)
        monkeypatch.setenv("ALERT_TOPIC_ARN", "arn:aws:sns:ap-south-1:1:topic")
        return sns

    return install


def test_reports_only_certificates_inside_threshold(fakes) -> None:
    fakes(
        {
            "soon": ("ACTIVE", NOW + timedelta(days=10)),
            "edge": ("INACTIVE", NOW + timedelta(days=30, hours=1)),
            "later": ("ACTIVE", NOW + timedelta(days=200)),
            "gone": ("REVOKED", NOW + timedelta(days=1)),
        }
    )
    report = ce.check(now=NOW)

    assert report["certificatesChecked"] == 3  # revoked certificates are skipped
    assert [c["certificateId"] for c in report["expiring"]] == ["soon", "edge"]
    assert report["expiring"][0]["daysRemaining"] == 10
    assert report["expiring"][0]["things"] == ["thing-soon"]


def test_handler_alerts_only_when_something_expires(fakes) -> None:
    sns = fakes({"later": ("ACTIVE", datetime.now(timezone.utc) + timedelta(days=9000))})
    report = ce.handler({}, None)
    assert report["expiringCount"] == 0 and sns.published == []

    sns = fakes({"soon": ("ACTIVE", datetime.now(timezone.utc) + timedelta(days=3))})
    report = ce.handler({}, None)
    assert report["expiringCount"] == 1 and len(sns.published) == 1
    assert "1 certificate(s)" in sns.published[0]["Subject"]


def test_days_remaining_handles_past_dates() -> None:
    assert ce.days_remaining(NOW - timedelta(days=2), NOW) == -2
