"""Weekly report of AWS IoT certificates that expire within THRESHOLD_DAYS."""

from __future__ import annotations

import json
import logging
import os
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
    log = logging.getLogger("cert_expiry")
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
def _sns() -> Any:
    return boto3.client("sns")


def days_remaining(not_after: datetime, now: datetime) -> int:
    return int((not_after - now).total_seconds() // 86400)


def inspect_certificate(cert: dict[str, Any], now: datetime) -> dict[str, Any]:
    iot = _iot()
    description = iot.describe_certificate(certificateId=cert["certificateId"])["certificateDescription"]
    not_after: datetime = description["validity"]["notAfter"]
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    things = iot.list_principal_things(principal=cert["certificateArn"]).get("things", [])
    return {
        "certificateId": cert["certificateId"],
        "things": things,
        "status": description["status"],
        "notAfter": not_after.isoformat(),
        "daysRemaining": days_remaining(not_after, now),
    }


def check(now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    threshold = int(os.environ.get("THRESHOLD_DAYS", "30"))

    certificates = []
    errors = []
    for page in _iot().get_paginator("list_certificates").paginate():
        for cert in page.get("certificates", []):
            if cert.get("status") == "REVOKED":
                continue
            try:
                certificates.append(inspect_certificate(cert, now))
            except ClientError as exc:
                errors.append({"certificateId": cert["certificateId"], "error": exc.response["Error"]["Code"]})

    certificates.sort(key=lambda c: c["daysRemaining"])
    expiring = [c for c in certificates if c["daysRemaining"] <= threshold]
    return {
        "checkedAt": now.isoformat(),
        "thresholdDays": threshold,
        "certificatesChecked": len(certificates),
        "expiringCount": len(expiring),
        "expiring": expiring,
        "soonestExpiry": certificates[0] if certificates else None,
        "errors": errors,
    }


def handler(event: dict[str, Any] | None = None, context: Any = None) -> dict[str, Any]:
    report = check()
    summary = {k: report[k] for k in ("thresholdDays", "certificatesChecked", "expiringCount", "soonestExpiry")}

    if report["expiring"]:
        logger.warning("certificates expiring soon", extra={"fields": {**summary, "expiring": report["expiring"]}})
        topic = os.environ.get("ALERT_TOPIC_ARN")
        if topic:
            _sns().publish(
                TopicArn=topic,
                Subject=f"iot-project: {report['expiringCount']} certificate(s) expire within {report['thresholdDays']} days",
                Message=json.dumps(report, indent=2, default=str),
            )
    else:
        logger.info("no certificates expiring soon", extra={"fields": summary})

    if report["errors"]:
        logger.error("some certificates could not be inspected", extra={"fields": {"errors": report["errors"]}})
    return report
