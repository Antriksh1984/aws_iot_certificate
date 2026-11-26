"""Store sensor telemetry routed by the IoT rule into DynamoDB.

Rule SQL: SELECT *, topic(2) AS deviceId, timestamp() AS ts FROM 'sensors/+/telemetry'
"""

from __future__ import annotations

import json
import logging
import os
import time
from decimal import Decimal
from functools import cache
from typing import Any

import boto3

READINGS = ("temperature", "humidity", "pressure")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {"level": record.levelname, "message": record.getMessage(), "logger": record.name}
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def _logger() -> logging.Logger:
    log = logging.getLogger("telemetry_processor")
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        log.addHandler(handler)
        log.propagate = False
    log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
    return log


logger = _logger()


@cache
def _table() -> Any:
    return boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])


class InvalidTelemetry(ValueError):
    pass


def build_item(event: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """Validate a telemetry event and turn it into a DynamoDB item."""
    device_id = event.get("deviceId")
    if not isinstance(device_id, str) or not device_id:
        raise InvalidTelemetry("missing deviceId")

    ts = event.get("ts")
    if not isinstance(ts, (int, float)):
        raise InvalidTelemetry("missing ts")

    readings: dict[str, Decimal] = {}
    for name in READINGS:
        value = event.get(name)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidTelemetry(f"{name} is not numeric")
        readings[name] = Decimal(str(value))
    if not readings:
        raise InvalidTelemetry("no sensor readings")

    ttl_days = int(os.environ.get("TTL_DAYS", "30"))
    now = time.time() if now is None else now
    item: dict[str, Any] = {
        "deviceId": device_id,
        "ts": int(ts),
        "receivedAt": int(now * 1000),
        "expiresAt": int(now) + ttl_days * 86400,
        **readings,
    }
    for key in ("seq", "sentAt", "status"):
        if key in event and isinstance(event[key], (str, int)) and not isinstance(event[key], bool):
            item[key] = event[key]
    return item


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    try:
        item = build_item(event)
    except InvalidTelemetry as exc:
        # Rejected payloads are logged, not retried: a bad message will never become valid.
        logger.warning("telemetry rejected", extra={"fields": {"reason": str(exc), "deviceId": event.get("deviceId")}})
        return {"stored": False, "reason": str(exc)}

    _table().put_item(Item=item)
    # Readings go in the log as numbers so the Grafana dashboard can chart them with Logs Insights.
    readings = {name: float(item[name]) for name in READINGS if name in item}
    logger.info("telemetry stored", extra={"fields": {"deviceId": item["deviceId"], "ts": item["ts"], **readings}})
    return {"stored": True, "deviceId": item["deviceId"], "ts": item["ts"]}
