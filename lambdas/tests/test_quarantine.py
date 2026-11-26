from __future__ import annotations

import json
from typing import Any

import pytest

import quarantine as q
from conftest import clear_client_caches, create_events_table


def sns_event(message: Any, message_id: str = "msg-1") -> dict[str, Any]:
    body = message if isinstance(message, str) else json.dumps(message)
    return {"Records": [{"EventSource": "aws:sns", "Sns": {"MessageId": message_id, "Message": body}}]}


VIOLATION = {
    "violationEventType": "in-alarm",
    "thingName": "iot-project-rogue-001",
    "securityProfileName": "iot-project-security-profile",
    "behavior": {"name": "excessive-disconnects", "metric": "aws:num-disconnects"},
    "metricValue": {"count": 6},
    "violationId": "v-123",
}


@pytest.fixture
def setup(iot_setup: dict[str, Any], env: pytest.MonkeyPatch) -> dict[str, Any]:
    clear_client_caches(q)
    iot_setup["table"] = create_events_table()
    return iot_setup


def policies(iot: Any, cert_arn: str) -> list[str]:
    return sorted(p["policyName"] for p in iot.list_attached_policies(target=cert_arn)["policies"])


def status(iot: Any, cert: dict[str, Any]) -> str:
    return iot.describe_certificate(certificateId=cert["certificateId"])["certificateDescription"]["status"]


def test_violation_quarantines_only_the_offending_device(setup: dict[str, Any]) -> None:
    iot, rogue, sensor = setup["iot"], setup["rogue"], setup["sensor"]

    result = q.handler(sns_event(VIOLATION))

    assert result["results"][0]["outcome"] == "quarantined"
    assert policies(iot, rogue["certificateArn"]) == ["iot-project-quarantine-policy"]
    assert status(iot, rogue) == "INACTIVE"
    # The well-behaved sensor is untouched.
    assert policies(iot, sensor["certificateArn"]) == ["iot-project-sensor-policy"]
    assert status(iot, sensor) == "ACTIVE"

    item = setup["table"].get_item(Key={"eventId": "quarantine-v-123"})["Item"]
    assert item["deviceId"] == "iot-project-rogue-001"
    assert item["source"] == "device-defender"
    assert "excessive-disconnects" in item["reason"]


def test_is_idempotent(setup: dict[str, Any]) -> None:
    q.handler(sns_event(VIOLATION))
    second = q.handler(sns_event(VIOLATION))

    assert second["results"][0]["outcome"] == "already-quarantined"
    assert second["results"][0]["recorded"] is False  # same violationId -> no duplicate record
    assert policies(setup["iot"], setup["rogue"]["certificateArn"]) == ["iot-project-quarantine-policy"]


@pytest.mark.parametrize(
    "message",
    [
        {**VIOLATION, "violationEventType": "alarm-cleared"},
        {**VIOLATION, "violationEventType": "alarm-invalidated"},
        {"AlarmName": "iot-project-connect-auth-errors", "NewStateValue": "ALARM"},
        "plain text budget notification",
    ],
)
def test_ignores_non_violation_messages(setup: dict[str, Any], message: Any) -> None:
    result = q.handler(sns_event(message))

    assert result == {"processed": 0, "results": []}
    assert status(setup["iot"], setup["rogue"]) == "ACTIVE"


def test_manual_invocation(setup: dict[str, Any]) -> None:
    result = q.handler({"thingName": "iot-project-rogue-001", "reason": "demo"})

    assert result["results"][0]["outcome"] == "quarantined"
    items = setup["table"].scan()["Items"]
    assert len(items) == 1 and items[0]["source"] == "manual" and items[0]["reason"] == "demo"


def test_refuses_devices_outside_the_project(setup: dict[str, Any]) -> None:
    result = q.handler({"thingName": "someone-elses-thing"})
    assert result["results"][0]["outcome"] == "refused"


def test_unknown_event_is_ignored(setup: dict[str, Any]) -> None:
    assert q.handler({"hello": "world"}) == {"processed": 0, "results": []}
