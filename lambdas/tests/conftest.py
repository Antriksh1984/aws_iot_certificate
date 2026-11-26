from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Iterator

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

REGION = "ap-south-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def aws() -> Iterator[None]:
    with mock_aws():
        yield


def clear_client_caches(*modules: Any) -> None:
    """Lambda modules cache boto3 clients; reset them so each test gets fresh moto clients."""
    for module in modules:
        for name in dir(module):
            attr = getattr(module, name)
            if callable(attr) and hasattr(attr, "cache_clear"):
                attr.cache_clear()


def create_events_table(name: str = "iot-project-security-events") -> Any:
    return boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName=name,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "eventId", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "eventId", "AttributeType": "S"},
            {"AttributeName": "deviceId", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "deviceId-timestamp-index",
                "KeySchema": [
                    {"AttributeName": "deviceId", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def create_device(iot: Any, thing_name: str, policy_name: str) -> dict[str, Any]:
    iot.create_thing(thingName=thing_name)
    cert = iot.create_keys_and_certificate(setAsActive=True)
    iot.attach_thing_principal(thingName=thing_name, principal=cert["certificateArn"])
    iot.attach_policy(policyName=policy_name, target=cert["certificateArn"])
    return cert


@pytest.fixture
def iot_setup(aws: None) -> dict[str, Any]:
    iot = boto3.client("iot", region_name=REGION)
    iot.create_policy(policyName="iot-project-sensor-policy", policyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iot:Connect","Resource":"*"}]}')
    iot.create_policy(policyName="iot-project-quarantine-policy", policyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iot:*","Resource":"*"}]}')
    rogue = create_device(iot, "iot-project-rogue-001", "iot-project-sensor-policy")
    sensor = create_device(iot, "iot-project-sensor-001", "iot-project-sensor-policy")
    return {"iot": iot, "rogue": rogue, "sensor": sensor}


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    values = {
        "TABLE_NAME": "iot-project-telemetry",
        "EVENTS_TABLE": "iot-project-security-events",
        "METRICS_TABLE": "iot-project-device-metrics",
        "QUARANTINE_POLICY_NAME": "iot-project-quarantine-policy",
        "THING_PREFIX": "iot-project-",
        "TTL_DAYS": "30",
        "THRESHOLD_DAYS": "30",
        "WINDOW_SECONDS": "300",
        "MAX_AUTH_FAILURES": "5",
        "MAX_CONNECTION_ATTEMPTS": "10",
        "MAX_DISCONNECTS": "5",
        "MAX_MESSAGE_BYTES": "1024",
        "SECURITY_PROFILE_NAME": "iot-project-security-profile",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
