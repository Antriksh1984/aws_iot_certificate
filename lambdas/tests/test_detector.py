from __future__ import annotations

import base64
import gzip
import json
from types import SimpleNamespace
from typing import Any

import boto3
import pytest

import detector as d
from conftest import REGION, clear_client_caches, create_events_table

CONTEXT = SimpleNamespace(invoked_function_arn="arn:aws:lambda:ap-south-1:123456789012:function:iot-project-detector")


@pytest.fixture
def setup(iot_setup: dict[str, Any], env: pytest.MonkeyPatch) -> dict[str, Any]:
    clear_client_caches(d)
    d._thing_cache.clear()
    sns = boto3.client("sns", region_name=REGION)
    topic = sns.create_topic(Name="iot-project-security-alerts")["TopicArn"]
    env.setenv("ALERT_TOPIC_ARN", topic)
    sqs = boto3.client("sqs", region_name=REGION)
    queue_url = sqs.create_queue(QueueName="capture")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn, Attributes={"RawMessageDelivery": "true"})
    boto3.resource("dynamodb", region_name=REGION).create_table(
        TableName="iot-project-device-metrics",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "deviceId", "KeyType": "HASH"}, {"AttributeName": "metricWindow", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "deviceId", "AttributeType": "S"}, {"AttributeName": "metricWindow", "AttributeType": "S"}],
    )
    iot_setup.update(events=create_events_table(), sqs=sqs, queue_url=queue_url)
    return iot_setup


def published(setup: dict[str, Any]) -> list[dict[str, Any]]:
    messages = setup["sqs"].receive_message(QueueUrl=setup["queue_url"], MaxNumberOfMessages=10).get("Messages", [])
    return [json.loads(m["Body"]) for m in messages]


def lifecycle(cert: dict[str, Any], event_type: str, client_id: str = "iot-project-rogue-001") -> dict[str, Any]:
    return {"clientId": client_id, "eventType": event_type, "principalIdentifier": cert["certificateId"], "timestamp": 1}


def logs_event(entries: list[dict[str, Any]]) -> dict[str, Any]:
    payload = {"logEvents": [{"id": str(i), "timestamp": 1, "message": json.dumps(e)} for i, e in enumerate(entries)]}
    return {"awslogs": {"data": base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}


def test_disconnect_threshold_raises_one_defender_format_violation(setup: dict[str, Any]) -> None:
    rogue = setup["rogue"]
    results = [d.handler(lifecycle(rogue, "disconnected"), CONTEXT) for _ in range(8)]

    assert [len(r["violations"]) for r in results] == [0, 0, 0, 0, 0, 1, 0, 0]  # fires on the 6th (> 5)
    [message] = published(setup)
    assert message["violationEventType"] == "in-alarm"
    assert message["thingName"] == "iot-project-rogue-001"
    assert message["behavior"]["metric"] == "aws:num-disconnects"
    assert message["metricValue"] == {"count": 6}
    events = setup["events"].scan()["Items"]
    assert [e["eventType"] for e in events] == ["VIOLATION"]


def test_attributes_by_certificate_not_claimed_client_id(setup: dict[str, Any]) -> None:
    # The rogue certificate tries to connect as sensor-001: the failure must count against the rogue.
    entry = {
        "status": "Failure",
        "eventType": "Connect",
        "reason": "AUTHORIZATION_FAILURE",
        "clientId": "iot-project-sensor-001",
        "principalId": setup["rogue"]["certificateId"],
    }
    for _ in range(6):
        d.handler(logs_event([entry]), CONTEXT)

    [message] = published(setup)
    assert message["thingName"] == "iot-project-rogue-001"
    assert message["behavior"]["metric"] == "aws:num-authorization-failures"


def test_log_batch_counts_auth_failures_and_connection_attempts(setup: dict[str, Any]) -> None:
    publish_denied = {"status": "Failure", "eventType": "Publish-In", "reason": "AUTHORIZATION_FAILURE", "clientId": "iot-project-rogue-001", "principalId": setup["rogue"]["certificateId"], "topicName": "sensors/iot-project-sensor-001/telemetry"}
    result = d.handler(logs_event([publish_denied] * 3 + [{"status": "Success"}]), CONTEXT)
    assert result == {"counted": 3, "violations": []}


def test_oversized_message_alerts_once_per_window(setup: dict[str, Any]) -> None:
    big = {"clientId": "iot-project-rogue-001", "principal": setup["rogue"]["certificateId"], "topic": "sensors/iot-project-rogue-001/telemetry", "payloadB64": base64.b64encode(b"x" * 4096).decode()}
    first = d.handler(big, CONTEXT)
    second = d.handler(big, CONTEXT)

    assert len(first["violations"]) == 1 and second["violations"] == []
    [message] = published(setup)
    assert message["metricValue"] == {"count": 4096}


def test_message_at_limit_is_not_a_violation(setup: dict[str, Any]) -> None:
    ok = {"clientId": "x", "principal": setup["rogue"]["certificateId"], "payloadB64": base64.b64encode(b"x" * 1024).decode()}
    assert d.handler(ok, CONTEXT) == {"counted": 0, "violations": []}


def test_well_behaved_sensor_never_alerts(setup: dict[str, Any]) -> None:
    sensor = setup["sensor"]
    for _ in range(3):
        d.handler(lifecycle(sensor, "connected", "iot-project-sensor-001"), CONTEXT)
        d.handler(lifecycle(sensor, "disconnected", "iot-project-sensor-001"), CONTEXT)
    assert published(setup) == []


def test_connect_failed_lifecycle_counts_as_connection_attempt(setup: dict[str, Any]) -> None:
    rogue = setup["rogue"]
    for _ in range(10):
        d.handler(lifecycle(rogue, "connected"), CONTEXT)
    result = d.handler(lifecycle(rogue, "connect_failed", "iot-project-sensor-001"), CONTEXT)

    assert len(result["violations"]) == 1
    [message] = published(setup)
    assert message["thingName"] == "iot-project-rogue-001"
    assert message["behavior"]["metric"] == "aws:num-connection-attempts"


def test_failed_connect_log_is_not_double_counted_as_connection_attempt(setup: dict[str, Any]) -> None:
    entry = {"status": "Failure", "eventType": "Connect", "reason": "AUTHORIZATION_FAILURE", "clientId": "iot-project-rogue-001", "principalId": setup["rogue"]["certificateId"]}
    assert d.handler(logs_event([entry]), CONTEXT) == {"counted": 1, "violations": []}


def test_alerts_again_after_counters_are_reset(setup: dict[str, Any]) -> None:
    rogue = setup["rogue"]
    for _ in range(6):
        d.handler(lifecycle(rogue, "disconnected"), CONTEXT)
    metrics = boto3.resource("dynamodb", region_name=REGION).Table("iot-project-device-metrics")
    for item in metrics.scan()["Items"]:  # what `emulator.py reset` does
        metrics.delete_item(Key={"deviceId": item["deviceId"], "metricWindow": item["metricWindow"]})
    results = [d.handler(lifecycle(rogue, "disconnected"), CONTEXT) for _ in range(6)]

    assert len(results[-1]["violations"]) == 1
    assert len(published(setup)) == 2
    assert len(setup["events"].scan()["Items"]) == 2


def test_unknown_certificate_is_not_attributed(setup: dict[str, Any]) -> None:
    event = {"clientId": "iot-project-sensor-001", "eventType": "disconnected", "principalIdentifier": "f" * 64}
    assert d.handler(event, CONTEXT) == {"counted": 0, "violations": []}
