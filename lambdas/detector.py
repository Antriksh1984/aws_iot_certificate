"""Self-managed replacement for AWS IoT Device Defender Rules Detect (cloud-side metrics).

Inputs:
  * IoT lifecycle events ($aws/events/presence/...)       -> connection attempts (connected and
                                                             connect_failed), disconnects
  * CloudWatch Logs subscription on AWSIotLogsV2 failures -> authorization failures
  * IoT rule over oversized messages on sensors/#         -> message byte size

Each observation is attributed to the thing that owns the *certificate* that made it
(not the client ID the device claims), counted per fixed window in DynamoDB, and when a
threshold is crossed a Device Defender-format "in-alarm" message is published to SNS.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cache
from typing import Any

import boto3
from botocore.exceptions import ClientError


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {"level": record.levelname, "message": record.getMessage(), "logger": record.name}
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def _logger() -> logging.Logger:
    log = logging.getLogger("detector")
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        log.addHandler(handler)
        log.propagate = False
    log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    return log


logger = _logger()

CERT_ID = re.compile(r"\b[0-9a-f]{64}\b")


@dataclass(frozen=True)
class Behavior:
    name: str
    metric: str
    limit_env: str
    windowed: bool  # count events per window; otherwise the value itself is compared

    @property
    def limit(self) -> int:
        return int(os.environ[self.limit_env])


AUTH_FAILURES = Behavior("excessive-authorization-failures", "aws:num-authorization-failures", "MAX_AUTH_FAILURES", True)
CONNECTION_ATTEMPTS = Behavior("excessive-connection-attempts", "aws:num-connection-attempts", "MAX_CONNECTION_ATTEMPTS", True)
DISCONNECTS = Behavior("excessive-disconnects", "aws:num-disconnects", "MAX_DISCONNECTS", True)
MESSAGE_SIZE = Behavior("oversized-messages", "aws:message-byte-size", "MAX_MESSAGE_BYTES", False)


@dataclass(frozen=True)
class Observation:
    behavior: Behavior
    principal: str | None
    client_id: str | None
    value: int = 1
    detail: str = ""


@cache
def _iot() -> Any:
    return boto3.client("iot")


@cache
def _sns() -> Any:
    return boto3.client("sns")


@cache
def _table(env_name: str) -> Any:
    return boto3.resource("dynamodb").Table(os.environ[env_name])


def _cert_id(principal: Any) -> str | None:
    if not isinstance(principal, str):
        return None
    match = CERT_ID.search(principal)
    return match.group(0) if match else None


# ---------------------------------------------------------------- event classification


def _from_iot_log(entry: dict[str, Any]) -> list[Observation]:
    # Failed connects are counted as connection attempts from the connect_failed lifecycle
    # event instead, so here they only count as authorization failures.
    if entry.get("status") != "Failure" or entry.get("reason") != "AUTHORIZATION_FAILURE":
        return []
    detail = f"{entry.get('eventType')}: {entry.get('reason')} {entry.get('topicName', '')}".strip()
    return [Observation(AUTH_FAILURES, entry.get("principalId"), entry.get("clientId"), detail=detail)]


LIFECYCLE = {"connected": CONNECTION_ATTEMPTS, "connect_failed": CONNECTION_ATTEMPTS, "disconnected": DISCONNECTS}


def classify(event: dict[str, Any]) -> list[Observation]:
    """Turn any of the three input shapes into observations."""
    if "awslogs" in event:
        payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
        observations: list[Observation] = []
        for log_event in payload.get("logEvents", []):
            try:
                entry = json.loads(log_event["message"])
            except (KeyError, json.JSONDecodeError):
                continue
            observations.extend(_from_iot_log(entry))
        return observations

    if event.get("eventType") in LIFECYCLE:
        behavior = LIFECYCLE[event["eventType"]]
        detail = event.get("disconnectReason") or event.get("failureReason") or event["eventType"]
        return [Observation(behavior, event.get("principalIdentifier"), event.get("clientId"), detail=detail)]

    if "payloadB64" in event:
        size = len(base64.b64decode(event["payloadB64"]))
        if size > MESSAGE_SIZE.limit:
            return [Observation(MESSAGE_SIZE, event.get("principal"), event.get("clientId"), value=size, detail=event.get("topic", ""))]
        return []

    logger.info("ignored unrecognised event", extra={"fields": {"keys": sorted(event), "eventType": event.get("eventType")}})
    return []


# ---------------------------------------------------------------- attribution


_thing_cache: dict[str, list[str]] = {}


def resolve_things(observation: Observation, account_id: str) -> list[str]:
    """Things attached to the certificate that produced the observation."""
    prefix = os.environ.get("THING_PREFIX", "iot-project-")
    cert_id = _cert_id(observation.principal)
    if cert_id is None:
        # No certificate in the event (rare): fall back to the claimed client ID.
        client = observation.client_id
        return [client] if isinstance(client, str) and client.startswith(prefix) else []

    if cert_id not in _thing_cache:
        region = os.environ.get("AWS_REGION", "ap-south-1")
        arn = f"arn:aws:iot:{region}:{account_id}:cert/{cert_id}"
        try:
            things = _iot().list_principal_things(principal=arn).get("things", [])
        except ClientError as exc:
            logger.warning("could not resolve certificate", extra={"fields": {"certificateId": cert_id, "error": exc.response["Error"]["Code"]}})
            things = []
        _thing_cache[cert_id] = [t for t in things if t.startswith(prefix)]
    return _thing_cache[cert_id]


# ---------------------------------------------------------------- counting and alerting


def _count(thing: str, behavior: Behavior, window_start: int, window: int, now: float) -> tuple[int, str]:
    """Atomically increment the window counter. Returns (count, counter creation time)."""
    result = _table("METRICS_TABLE").update_item(
        Key={"deviceId": thing, "metricWindow": f"{behavior.metric}#{window_start}"},
        UpdateExpression="ADD #c :one SET expiresAt = :exp, windowSeconds = :w, createdAt = if_not_exists(createdAt, :now)",
        ExpressionAttributeNames={"#c": "count"},
        ExpressionAttributeValues={":one": 1, ":exp": window_start + 86400, ":w": window, ":now": str(now)},
        ReturnValues="ALL_NEW",
    )
    return int(result["Attributes"]["count"]), str(result["Attributes"]["createdAt"])


def evaluate(thing: str, observation: Observation, now: float) -> dict[str, Any] | None:
    """Count the observation; return a violation exactly once per device/behaviour/window."""
    behavior = observation.behavior
    window = int(os.environ.get("WINDOW_SECONDS", "300"))
    window_start = int(now // window) * window
    count, created_at = _count(thing, behavior, window_start, window, now)

    if behavior.windowed:
        if count != behavior.limit + 1:
            return None
        metric_value: dict[str, Any] = {"count": count}
        criteria: dict[str, Any] = {"comparisonOperator": "greater-than", "value": {"count": behavior.limit}, "durationSeconds": window}
    else:
        if count != 1:
            return None
        metric_value = {"count": observation.value}
        criteria = {"comparisonOperator": "greater-than", "value": {"count": behavior.limit}}

    # Stable for retries of the same counter, new once the counter is reset (e.g. after un-quarantine).
    violation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{thing}/{behavior.metric}/{window_start}/{created_at}"))
    return {
        "violationEventTime": int(now * 1000),
        "thingName": thing,
        "securityProfileName": os.environ.get("SECURITY_PROFILE_NAME", "iot-project-security-profile"),
        "behavior": {"name": behavior.name, "metric": behavior.metric, "criteria": criteria},
        "violationEventType": "in-alarm",
        "metricValue": metric_value,
        "violationId": violation_id,
        "detector": "iot-project-detector",
        "summary": f"{thing} breached {behavior.name}: {metric_value['count']} > {behavior.limit} ({observation.detail or behavior.metric})",
    }


def raise_violation(violation: dict[str, Any]) -> bool:
    """Record the violation, then alert. Returns False if it was already raised."""
    ttl_days = int(os.environ.get("TTL_DAYS", "30"))
    try:
        _table("EVENTS_TABLE").put_item(
            Item={
                "eventId": f"violation-{violation['violationId']}",
                "deviceId": violation["thingName"],
                "timestamp": datetime.fromtimestamp(violation["violationEventTime"] / 1000, timezone.utc).isoformat(timespec="milliseconds"),
                "eventType": "VIOLATION",
                "behavior": violation["behavior"]["name"],
                "metric": violation["behavior"]["metric"],
                "metricValue": violation["metricValue"]["count"],
                "summary": violation["summary"],
                "expiresAt": int(time.time()) + ttl_days * 86400,
            },
            ConditionExpression="attribute_not_exists(eventId)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise

    _sns().publish(
        TopicArn=os.environ["ALERT_TOPIC_ARN"],
        Subject=f"iot-project violation: {violation['thingName']} {violation['behavior']['name']}"[:100],
        Message=json.dumps(violation),
    )
    logger.warning("violation detected", extra={"fields": violation})
    return True


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    account_id = context.invoked_function_arn.split(":")[4] if context else os.environ.get("ACCOUNT_ID", "")
    now = time.time()
    counted, violations = 0, []

    for observation in classify(event):
        things = resolve_things(observation, account_id)
        if not things:
            logger.info("unattributed observation", extra={"fields": {"metric": observation.behavior.metric, "clientId": observation.client_id}})
            continue
        for thing in things:
            counted += 1
            violation = evaluate(thing, observation, now)
            if violation and raise_violation(violation):
                violations.append(violation["violationId"])

    if counted:
        logger.info("observations counted", extra={"fields": {"counted": counted, "violations": len(violations)}})
    return {"counted": counted, "violations": violations}
