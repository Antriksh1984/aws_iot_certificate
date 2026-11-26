"""Generate grafana/dashboards/iot-project.json.

The dashboard JSON is generated so the panels stay consistent. Edit this file, then run:
    python grafana/build_dashboard.py
Grafana reloads the file within 10 seconds.
"""
import json
import sys
from pathlib import Path

DS = {"type": "cloudwatch", "uid": "iot-project-cloudwatch"}
P = "iot-project"
LG_TELEMETRY = f"/aws/lambda/{P}-telemetry-processor"
LG_DETECTOR = f"/aws/lambda/{P}-detector"
LG_QUARANTINE = f"/aws/lambda/{P}-quarantine"
LG_IOT = "AWSIotLogsV2"
FUNCTIONS = [f"{P}-telemetry-processor", f"{P}-detector", f"{P}-quarantine", f"{P}-cert-expiry"]

_id = 0


def pid():
    global _id
    _id += 1
    return _id


def metric(ref, ns, name, dims, label, stat="Sum"):
    return {
        "refId": ref, "datasource": DS, "queryMode": "Metrics", "region": "default",
        "namespace": ns, "metricName": name, "dimensions": dims, "statistic": stat,
        "period": "60", "matchExact": True, "metricQueryType": 0, "metricEditorMode": 0,
        "id": "", "expression": "", "label": label,
    }


def filled(ref, ns, name, dims, label):
    """Per-minute Sum with quiet minutes filled with 0, so sparse events draw as narrow bars."""
    schema = ",".join([ns, *dims])
    terms = " ".join([f'MetricName="{name}"', *[f'{k}="{v}"' for k, v in dims.items()]])
    return {
        "refId": ref, "datasource": DS, "queryMode": "Metrics", "region": "default",
        "metricQueryType": 0, "metricEditorMode": 1,
        "expression": f"FILL(SEARCH('{{{schema}}} {terms}', 'Sum', 60), 0)",
        "id": "", "label": label, "period": "60", "namespace": "", "metricName": "",
        "dimensions": {}, "statistic": "Sum", "matchExact": True,
    }


def logs(ref, groups, expression, stats_groups=None):
    q = {
        "refId": ref, "datasource": DS, "queryMode": "Logs", "queryLanguage": "CWLI",
        "region": "default", "logGroupNames": groups, "expression": expression, "id": "",
    }
    if stats_groups:
        q["statsGroups"] = stats_groups
    return q


def row(title, y):
    return {"type": "row", "id": pid(), "title": title, "collapsed": False, "panels": [],
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}}


def stat(title, targets, x, y, w, color, description, unit="none"):
    return {
        "type": "stat", "id": pid(), "title": title, "description": description, "datasource": DS,
        "gridPos": {"h": 5, "w": w, "x": x, "y": y}, "targets": targets,
        "options": {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                    "colorMode": "background", "graphMode": "area", "textMode": "value_and_name" if len(targets) > 1 else "value",
                    "justifyMode": "center", "orientation": "horizontal", "wideLayout": True},
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 0, "noValue": "0",
                                      "color": {"mode": "fixed", "fixedColor": color}}, "overrides": []},
    }


def organize(order):
    """Hide Grafana's internal log columns, show @timestamp as 'time' and fix column order."""
    # Grafana may surface @timestamp as "Time"; handle both names.
    index = {"@timestamp": 0, "Time": 0, **{name: i + 1 for i, name in enumerate(order)}}
    return [{"id": "organize", "options": {
        "excludeByName": {"__log__grafana_internal__": True, "__logstream__grafana_internal__": True},
        "renameByName": {"@timestamp": "time", "Time": "time"},
        "indexByName": index}}]


def timeseries(title, targets, x, y, w, h, description, unit="none", bars=False, display_name=None, stack=False,
               transformations=None):
    custom = {"drawStyle": "bars" if bars else "line", "lineWidth": 2, "fillOpacity": 60 if bars else 10,
              "pointSize": 5, "showPoints": "auto", "spanNulls": True, "barAlignment": 0,
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    defaults = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if display_name:
        defaults["displayName"] = display_name
    return {
        "type": "timeseries", "id": pid(), "title": title, "description": description, "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y}, "targets": targets,
        "transformations": transformations or [],
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "fieldConfig": {"defaults": defaults, "overrides": []},
    }


def table(title, targets, x, y, w, h, description, overrides=None, sort_by=None, transformations=None):
    return {
        "type": "table", "id": pid(), "title": title, "description": description, "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y}, "targets": targets,
        "transformations": transformations or [],
        "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False},
                    "sortBy": sort_by or []},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "filterable": False}},
                        "overrides": overrides or []},
    }


def colored_text(field, mapping):
    """Value mapping that colours a text column, e.g. ALLOWED green / BLOCKED red."""
    return {
        "matcher": {"id": "byName", "options": field},
        "properties": [
            {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}},
            {"id": "color", "value": {"mode": "fixed", "fixedColor": "transparent"}},
            {"id": "mappings", "value": [{"type": "value", "options": {
                k: {"text": text, "color": color, "index": i} for i, (k, (text, color)) in enumerate(mapping.items())}}]},
        ],
    }


def width(field, px):
    return {"matcher": {"id": "byName", "options": field}, "properties": [{"id": "custom.width", "value": px}]}


panels = []
y = 0

# ---------------------------------------------------------------- header
panels.append({
    "type": "text", "id": pid(), "title": "", "gridPos": {"h": 5, "w": 8, "x": 0, "y": y},
    "options": {"mode": "markdown", "content": (
        "### Per-device X.509 identity on AWS IoT Core\n"
        "**5 sensors + 1 rogue device**, emulated in Python, each with its **own certificate** (mutual TLS, port 8883).\n\n"
        "1. **Authenticate**: no valid certificate, no connection\n"
        "2. **Authorize**: a device may use only its own topics\n"
        "3. **Detect & respond**: misbehaviour → alert → automatic quarantine")},
})
panels.append(stat("Telemetry messages stored",
                   [metric("A", "AWS/Lambda", "Invocations", {"FunctionName": f"{P}-telemetry-processor"}, "Stored")],
                   8, y, 4, "green", "Readings written to DynamoDB in the selected time range."))
panels.append(stat("Blocked by AWS IoT",
                   [metric("A", "AWS/IoT", "PublishIn.AuthError", {"Protocol": "MQTT"}, "Publish"),
                    metric("B", "AWS/IoT", "Connect.AuthError", {"Protocol": "MQTT"}, "Connect"),
                    metric("C", "AWS/IoT", "Connection.AuthNError", {"Protocol": "MQTT"}, "Bad cert")],
                   12, y, 4, "orange",
                   "Publish: denied by the device policy. Connect: wrong client ID or quarantined certificate. "
                   "Bad cert: TLS rejected (self-signed, missing or mismatched certificate)."))
panels.append(stat("Violations detected",
                   [metric("A", P, "DeviceViolations", {}, "Violations")],
                   16, y, 4, "dark-orange", "Detector rule breaches (auth failures, reconnect storms, disconnects, oversized messages)."))
panels.append(stat("Devices quarantined",
                   [metric("A", P, "DevicesQuarantined", {}, "Quarantined")],
                   20, y, 4, "red", "Certificates set INACTIVE with the deny-all policy attached."))
y += 5

# ---------------------------------------------------------------- 1. fleet
panels.append(row("1 · Fleet telemetry: what good devices send", y))
y += 1
panels.append(timeseries(
    "Temperature by device (°C)",
    [logs("A", [LG_TELEMETRY],
          'filter message = "telemetry stored"\n| stats avg(temperature) as avgCelsius by bin(1m), deviceId',
          ["deviceId"])],
    0, y, 12, 8, "Average temperature per device per minute, from the telemetry Lambda.", unit="celsius",
    display_name="${__series.name}"))
panels.append(timeseries(
    "Messages stored per device per minute",
    [logs("A", [LG_TELEMETRY],
          'filter message = "telemetry stored"\n| stats count(*) as messages by bin(1m), deviceId',
          ["deviceId"])],
    12, y, 12, 8, "If a device goes quiet (e.g. the rogue after quarantine) its bars stop.", bars=True, stack=True,
    display_name="${__series.name}"))
y += 8
panels.append(table(
    "Latest reading per device",
    [logs("A", [LG_TELEMETRY],
          'filter message = "telemetry stored"\n'
          '| stats latest(temperature) as temperatureC, latest(humidity) as humidityPct, latest(pressure) as pressureHpa,'
          ' count(*) as messages, max(@timestamp) as lastSeen by deviceId\n| sort deviceId asc')],
    0, y, 24, 7, "One row per device: last reading and how many messages it sent in the time range."))
y += 7

# ---------------------------------------------------------------- 2. blocked
panels.append(row("2 · Attacks blocked by AWS IoT: authentication and least privilege", y))
y += 1
panels.append(timeseries(
    "Blocked per minute",
    [filled("A", "AWS/IoT", "PublishIn.AuthError", {"Protocol": "MQTT"}, "Publish denied (not its topic)"),
     filled("B", "AWS/IoT", "Connect.AuthError", {"Protocol": "MQTT"}, "Connect denied (wrong client ID / quarantined)"),
     filled("C", "AWS/IoT", "Connection.AuthNError", {"Protocol": "MQTT"}, "TLS rejected (no valid certificate)")],
    0, y, 9, 9, "AWS IoT metrics. Denied subscribes are answered with SUBACK NOT_AUTHORIZED and are not counted by AWS.",
    bars=True, stack=True))
panels.append(table(
    "What was blocked: AWS IoT log",
    [logs("A", [LG_IOT],
          'fields @timestamp, clientId as claimedClientId, eventType as action, topicName as topic, reason,'
          ' substr(principalId, 0, 10) as certificate\n| filter status = "Failure"\n| sort @timestamp desc\n| limit 100')],
    9, y, 15, 9,
    "Every denied action. 'certificate' is the real identity; 'claimedClientId' is what the device said it was. "
    "A rogue certificate claiming to be sensor-001 shows sensor-001 here but the rogue's certificate.",
    overrides=[colored_text("reason", {"AUTHORIZATION_FAILURE": ("DENIED by policy", "red")}),
               width("time", 200), width("certificate", 110), width("action", 100)],
    transformations=organize(["@timestamp", "claimedClientId", "certificate", "action", "topic", "reason"])))
y += 9

# ---------------------------------------------------------------- 3. detection & response
panels.append(row("3 · Detection and automatic response", y))
y += 1
panels.append(table(
    "Security timeline",
    [logs("A", [LG_DETECTOR, LG_QUARANTINE],
          'fields @timestamp, message as event, thingName as device, coalesce(summary, reason) as detail, outcome\n'
          '| filter message in ["violation detected", "device quarantined", "device already quarantined"]\n'
          '| sort @timestamp desc\n| limit 50')],
    0, y, 16, 9,
    "Detector violations and the quarantine Lambda's response, newest first. Quarantine = deny-all policy + certificate INACTIVE.",
    overrides=[colored_text("event", {"violation detected": ("⚠ VIOLATION", "orange"),
                                      "device quarantined": ("⛔ QUARANTINED", "red"),
                                      "device already quarantined": ("already quarantined", "dark-red")}),
               colored_text("outcome", {"quarantined": ("quarantined", "red"),
                                        "already-quarantined": ("no-op (idempotent)", "transparent")}),
               width("time", 200), width("event", 150), width("device", 170), width("outcome", 150)],
    transformations=organize(["@timestamp", "event", "device", "detail", "outcome"])))
panels.append(timeseries(
    "Violations and quarantines",
    [filled("A", P, "DeviceViolations", {}, "Violations"),
     filled("B", P, "DevicesQuarantined", {}, "Quarantines")],
    16, y, 8, 9, "Custom metrics from the detector and quarantine logs.", bars=True))
y += 9

# ---------------------------------------------------------------- 4. platform
panels.append(row("4 · Platform health", y))
y += 1
panels.append(timeseries(
    "Lambda invocations",
    [filled(chr(65 + i), "AWS/Lambda", "Invocations", {"FunctionName": fn}, fn.removeprefix(f"{P}-"))
     for i, fn in enumerate(FUNCTIONS)],
    0, y, 10, 7, "Every function is invoked by an event source: IoT rules, SNS or EventBridge.", bars=True))
panels.append(timeseries(
    "Lambda errors",
    [filled(chr(65 + i), "AWS/Lambda", "Errors", {"FunctionName": fn}, fn.removeprefix(f"{P}-"))
     for i, fn in enumerate(FUNCTIONS)],
    10, y, 7, 7, "Should stay at zero. Alarms email the alert topic if not.", bars=True))
panels.append(timeseries(
    "Successful connections",
    [filled("A", "AWS/IoT", "Connect.Success", {"Protocol": "MQTT"}, "Connect OK"),
     filled("B", "AWS/IoT", "PublishIn.Success", {"Protocol": "MQTT"}, "Publish OK")],
    17, y, 7, 7, "Accepted MQTT connections and publishes.", bars=True))

dashboard = {
    "uid": "iot-project",
    "title": "IoT Certificate Security · iot-project",
    "description": "Live view of the iot-project demo: fleet telemetry, blocked attacks, detection and quarantine.",
    "tags": ["iot-project", "aws-iot", "security"],
    "timezone": "browser",
    "editable": True,
    "graphTooltip": 1,
    "time": {"from": "now-30m", "to": "now"},
    "refresh": "10s",
    "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m"]},
    "schemaVersion": 41,
    "version": 1,
    "panels": panels,
    "templating": {"list": []},
    "annotations": {"list": []},
    "links": [],
}

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("dashboards") / "iot-project.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(dashboard, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out} with {len(panels)} panels")
