"""Quarantine a device: deny-all policy on its certificates and certificates set INACTIVE.

Triggered by Device Defender-format violation messages on the security-alerts SNS topic,
or invoked directly for the demo with {"thingName": "...", "reason": "..."}.
Safe to run repeatedly for the same device.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
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
    log = logging.getLogger("quarantine")
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        log.addHandler(handler)
        log.propagate = False
    log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    return log


logger = _logger()


@cache
def _iot() -> Any:
    return boto3.client("iot")


@cache
def _events_table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["EVENTS_TABLE"])


@dataclass
class QuarantineRequest:
    thing_name: str
    reason: str
    source: str
    event_id: str
    violation: dict[str, Any] = field(default_factory=dict)


def _describe_violation(message: dict[str, Any]) -> str:
    behavior = message.get("behavior") or {}
    name = behavior.get("name", "unknown-behavior")
    metric = behavior.get("metric", "unknown-metric")
    value = message.get("metricValue")
    return f"{name} ({metric}) value={json.dumps(value)}" if value is not None else f"{name} ({metric})"


def parse_requests(event: dict[str, Any]) -> list[QuarantineRequest]:
    """Extract quarantine requests; anything that is not an in-alarm violation is ignored."""
    if "Records" in event:
        requests = []
        for record in event["Records"]:
            sns = record.get("Sns") or {}
            try:
                message = json.loads(sns.get("Message", ""))
            except (TypeError, json.JSONDecodeError):
                logger.info("ignored non-JSON SNS message", extra={"fields": {"messageId": sns.get("MessageId")}})
                continue
            if not isinstance(message, dict) or message.get("violationEventType") != "in-alarm":
                logger.info(
                    "ignored non-violation message",
                    extra={"fields": {"messageId": sns.get("MessageId"), "violationEventType": message.get("violationEventType") if isinstance(message, dict) else None}},
                )
                continue
            thing_name = message.get("thingName")
            if not isinstance(thing_name, str) or not thing_name:
                logger.warning("violation without thingName", extra={"fields": {"messageId": sns.get("MessageId")}})
                continue
            requests.append(
                QuarantineRequest(
                    thing_name=thing_name,
                    reason=_describe_violation(message),
                    source="device-defender",
                    event_id=str(message.get("violationId") or sns.get("MessageId") or uuid.uuid4()),
                    violation=message,
                )
            )
        return requests

    thing_name = event.get("thingName")
    if isinstance(thing_name, str) and thing_name:
        return [
            QuarantineRequest(
                thing_name=thing_name,
                reason=str(event.get("reason") or "manual quarantine"),
                source="manual",
                event_id=f"manual-{uuid.uuid4()}",
            )
        ]

    logger.info("ignored event without Records or thingName")
    return []


def _paginate(operation: str, key: str, **kwargs: Any) -> list[Any]:
    paginator = _iot().get_paginator(operation)
    items: list[Any] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def isolate_certificate(cert_arn: str, quarantine_policy: str) -> dict[str, Any]:
    """Attach the deny-all policy first, then strip every other policy and deactivate."""
    iot = _iot()
    cert_id = cert_arn.rsplit("/", 1)[-1]
    attached = [p["policyName"] for p in _paginate("list_attached_policies", "policies", target=cert_arn)]

    attached_quarantine = False
    if quarantine_policy not in attached:
        iot.attach_policy(policyName=quarantine_policy, target=cert_arn)
        attached_quarantine = True

    detached = []
    for policy in attached:
        if policy != quarantine_policy:
            iot.detach_policy(policyName=policy, target=cert_arn)
            detached.append(policy)

    status = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]["status"]
    deactivated = False
    if status == "ACTIVE":
        iot.update_certificate(certificateId=cert_id, newStatus="INACTIVE")
        deactivated = True
        status = "INACTIVE"

    return {
        "certificateId": cert_id,
        "attachedQuarantinePolicy": attached_quarantine,
        "detachedPolicies": detached,
        "deactivated": deactivated,
        "status": status,
        "changed": attached_quarantine or bool(detached) or deactivated,
    }


def record_event(request: QuarantineRequest, outcome: str, certificates: list[dict[str, Any]]) -> bool:
    """Write the security event once per eventId (SNS may redeliver). Returns False on duplicate."""
    ttl_days = int(os.environ.get("TTL_DAYS", "30"))
    item: dict[str, Any] = {
        "eventId": f"quarantine-{request.event_id}",
        "deviceId": request.thing_name,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "eventType": "QUARANTINE",
        "outcome": outcome,
        "source": request.source,
        "reason": request.reason,
        "certificates": certificates,
        "expiresAt": int(time.time()) + ttl_days * 86400,
    }
    if request.violation:
        item["violation"] = json.dumps(request.violation)
    try:
        _events_table().put_item(Item=item, ConditionExpression="attribute_not_exists(eventId)")
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def quarantine(request: QuarantineRequest) -> dict[str, Any]:
    prefix = os.environ.get("THING_PREFIX", "iot-project-")
    quarantine_policy = os.environ["QUARANTINE_POLICY_NAME"]
    fields = {"thingName": request.thing_name, "source": request.source, "eventId": request.event_id}

    if not request.thing_name.startswith(prefix):
        logger.warning("refused: not a project device", extra={"fields": fields})
        return {"thingName": request.thing_name, "outcome": "refused", "reason": f"thing name must start with {prefix}"}

    principals = _paginate("list_thing_principals", "principals", thingName=request.thing_name)
    cert_arns = [p for p in principals if ":cert/" in p]
    if not cert_arns:
        logger.warning("no certificates attached", extra={"fields": fields})
        return {"thingName": request.thing_name, "outcome": "no-certificates"}

    certificates = [isolate_certificate(arn, quarantine_policy) for arn in cert_arns]
    outcome = "quarantined" if any(c["changed"] for c in certificates) else "already-quarantined"
    recorded = record_event(request, outcome, certificates)

    log_fields = {**fields, "outcome": outcome, "reason": request.reason, "certificates": certificates, "recorded": recorded}
    if outcome == "quarantined":
        logger.warning("device quarantined", extra={"fields": log_fields})
    else:
        logger.info("device already quarantined", extra={"fields": log_fields})
    return {"thingName": request.thing_name, "outcome": outcome, "certificates": certificates, "recorded": recorded}


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    results = []
    failures = 0
    for request in parse_requests(event):
        try:
            results.append(quarantine(request))
        except ClientError as exc:
            failures += 1
            logger.exception("quarantine failed", extra={"fields": {"thingName": request.thing_name, "error": exc.response["Error"]}})
            results.append({"thingName": request.thing_name, "outcome": "error", "error": exc.response["Error"]["Code"]})
    if failures:
        # Fail the invocation so SNS/Lambda retries; every step above is idempotent.
        raise RuntimeError(f"{failures} quarantine request(s) failed: {json.dumps(results, default=str)}")
    return {"processed": len(results), "results": results}
