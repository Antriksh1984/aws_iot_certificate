from __future__ import annotations

from decimal import Decimal

import boto3
import pytest

import telemetry_processor as tp
from conftest import REGION, clear_client_caches


@pytest.fixture
def table(aws: None, env: pytest.MonkeyPatch):
    clear_client_caches(tp)
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName="iot-project-telemetry",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "deviceId", "KeyType": "HASH"}, {"AttributeName": "ts", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "deviceId", "AttributeType": "S"}, {"AttributeName": "ts", "AttributeType": "N"}],
    )


EVENT = {"deviceId": "iot-project-sensor-001", "ts": 1760000000000, "temperature": 21.5, "humidity": 40, "pressure": 1012.3, "seq": 7}


def test_stores_item_with_ttl(table) -> None:
    result = tp.handler(dict(EVENT))

    assert result == {"stored": True, "deviceId": "iot-project-sensor-001", "ts": 1760000000000}
    item = table.get_item(Key={"deviceId": "iot-project-sensor-001", "ts": 1760000000000})["Item"]
    assert item["temperature"] == Decimal("21.5")
    assert item["seq"] == 7
    assert item["expiresAt"] > item["receivedAt"] // 1000


def test_ttl_is_thirty_days(env: pytest.MonkeyPatch) -> None:
    item = tp.build_item(dict(EVENT), now=1_000_000.0)
    assert item["expiresAt"] == 1_000_000 + 30 * 86400


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"deviceId": None}, "missing deviceId"),
        ({"ts": "yesterday"}, "missing ts"),
        ({"temperature": "hot"}, "temperature is not numeric"),
        ({"temperature": True}, "temperature is not numeric"),
    ],
)
def test_rejects_invalid_payloads(table, change: dict, reason: str) -> None:
    result = tp.handler({**EVENT, **change})
    assert result == {"stored": False, "reason": reason}
    assert table.scan()["Count"] == 0


def test_rejects_payload_without_readings(table) -> None:
    result = tp.handler({"deviceId": "iot-project-sensor-001", "ts": 1})
    assert result["reason"] == "no sensor readings"
