#!/usr/bin/env python3
"""Emulated IoT devices for the iot-project certificate-security demo.

Every device talks MQTT 5 over mutual TLS (port 8883) with its own X.509 certificate.
MQTT 5 lets AWS IoT answer a forbidden publish/subscribe with an explicit NOT_AUTHORIZED
reason code, so each scenario prints exactly what AWS allowed and what it blocked.

    python emulator.py fleet [--interval 60] [--duration 0]
    python emulator.py cross-topic sensor-002
    python emulator.py no-cert
    python emulator.py rogue
    python emulator.py stolen-cert [--duration 60]
    python emulator.py status
    python emulator.py quarantine rogue-001 [--reason "..."]
    python emulator.py reset rogue-001
    python emulator.py pre-destroy
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from awscrt import mqtt5
from awsiot import mqtt5_client_builder
from colorama import Fore, Style, just_fix_windows_console

ROOT = Path(__file__).resolve().parents[1]
INFRA_DIR = ROOT / "infra"
ROOT_CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
TIMEOUT = 10.0

_print_lock = threading.Lock()


# ---------------------------------------------------------------- console output


def _out(color: str, tag: str, who: str, text: str) -> None:
    stamp = datetime.now().strftime("%H:%M:%S")
    with _print_lock:
        print(f"{Style.DIM}{stamp}{Style.RESET_ALL} {color}{tag:<10}{Style.RESET_ALL} {Fore.WHITE}{who:<24}{Style.RESET_ALL} {text}", flush=True)


def attempt(who: str, text: str) -> None:
    _out(Fore.CYAN, "TRY", who, text)


def allowed(who: str, text: str) -> None:
    _out(Fore.GREEN, "ALLOWED", who, text)


def blocked(who: str, text: str) -> None:
    _out(Fore.RED, "BLOCKED", who, text)


def info(who: str, text: str) -> None:
    _out(Fore.YELLOW, "INFO", who, text)


def heading(text: str) -> None:
    with _print_lock:
        print(f"\n{Style.BRIGHT}{Fore.MAGENTA}== {text} =={Style.RESET_ALL}", flush=True)


@dataclass
class Scoreboard:
    """Tracks expected vs actual outcomes so a scenario can pass or fail as a whole."""

    rows: list[tuple[str, str, str]] = field(default_factory=list)

    def expect(self, action: str, expected: str, ok: bool) -> None:
        actual = "allowed" if ok else "blocked"
        self.rows.append((action, expected, actual))

    def report(self) -> bool:
        heading("Summary")
        passed = True
        for action, expected, actual in self.rows:
            good = expected == actual
            passed &= good
            mark = f"{Fore.GREEN}as expected{Style.RESET_ALL}" if good else f"{Fore.RED}UNEXPECTED{Style.RESET_ALL}"
            print(f"  {action:<62} expected {expected:<8} got {actual:<8} {mark}")
        verdict = f"{Fore.GREEN}PASS" if passed else f"{Fore.RED}FAIL"
        print(f"\n  {Style.BRIGHT}{verdict}{Style.RESET_ALL}")
        return passed


# ---------------------------------------------------------------- configuration


@dataclass
class Config:
    region: str
    endpoint: str
    thing_names: dict[str, str]
    cert_files: dict[str, dict[str, str]]
    certs_dir: Path
    telemetry_table: str
    security_events_table: str
    device_metrics_table: str
    lambda_functions: dict[str, str]
    sensor_policy: str
    quarantine_policy: str

    @property
    def root_ca(self) -> Path:
        return self.certs_dir / "AmazonRootCA1.pem"

    def key(self, name: str) -> str:
        """Accept 'sensor-002' or 'iot-project-sensor-002'."""
        short = name.removeprefix("iot-project-")
        if short not in self.thing_names:
            sys.exit(f"Unknown device '{name}'. Known: {', '.join(sorted(self.thing_names))}")
        return short

    def sensors(self) -> list[str]:
        return sorted(k for k in self.thing_names if k.startswith("sensor-"))


def load_config() -> Config:
    try:
        raw = subprocess.run(
            ["terraform", f"-chdir={INFRA_DIR}", "output", "-json"],
            check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Could not read Terraform outputs (is the stack deployed?): {exc}")
    outputs = {k: v["value"] for k, v in json.loads(raw).items()}
    if "iot_endpoint" not in outputs:
        sys.exit("Terraform outputs are empty - run 'make deploy' first.")
    config = Config(
        region=outputs["region"],
        endpoint=outputs["iot_endpoint"],
        thing_names=outputs["thing_names"],
        cert_files=outputs["cert_files"],
        certs_dir=Path(outputs["certs_dir"]),
        telemetry_table=outputs["telemetry_table"],
        security_events_table=outputs["security_events_table"],
        device_metrics_table=outputs["device_metrics_table"],
        lambda_functions=outputs["lambda_functions"],
        sensor_policy=outputs["sensor_policy_name"],
        quarantine_policy=outputs["quarantine_policy_name"],
    )
    ensure_root_ca(config.root_ca)
    return config


def ensure_root_ca(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(ROOT_CA_URL, timeout=30) as response:
        pem = response.read()
    if b"BEGIN CERTIFICATE" not in pem:
        sys.exit(f"Unexpected content downloading {ROOT_CA_URL}")
    path.write_bytes(pem)
    info("setup", f"downloaded Amazon Root CA 1 to {path}")


# ---------------------------------------------------------------- MQTT 5 device


class Device:
    """One MQTT 5 client using one certificate."""

    def __init__(
        self, cfg: Config, label: str, cert: Path, key: Path, client_id: str,
        auto_reconnect: bool = False, reconnect_delay_ms: int = 1000,
    ) -> None:
        self.cfg, self.label, self.cert, self.key, self.client_id = cfg, label, cert, key, client_id
        self.auto_reconnect = auto_reconnect
        self.reconnect_delay_ms = reconnect_delay_ms
        self.client: mqtt5.Client | None = None
        self.connected = threading.Event()
        self.failed = threading.Event()
        self.stopped = threading.Event()
        self.failure_detail = ""
        self.connects = 0
        self.disconnects: list[str] = []
        self.received: list[str] = []

    @classmethod
    def for_thing(cls, cfg: Config, key: str, client_id: str | None = None, label: str | None = None, **kwargs: Any) -> "Device":
        files = cfg.cert_files[key]
        thing = cfg.thing_names[key]
        return cls(cfg, label or thing, Path(files["certificate"]), Path(files["private_key"]), client_id or thing, **kwargs)

    # CRT callbacks run on CRT threads; keep them short.
    def _on_success(self, data: mqtt5.LifecycleConnectSuccessData) -> None:
        self.connects += 1
        self.failed.clear()
        self.connected.set()

    def _on_failure(self, data: mqtt5.LifecycleConnectFailureData) -> None:
        reason = data.connack_packet.reason_code.name if data.connack_packet else None
        self.failure_detail = f"CONNACK {reason}" if reason else f"{type(data.exception).__name__}: {data.exception}"
        self.failed.set()

    def _on_disconnect(self, data: mqtt5.LifecycleDisconnectData) -> None:
        reason = data.disconnect_packet.reason_code.name if data.disconnect_packet else str(data.exception)
        self.disconnects.append(reason)
        self.connected.clear()

    def _on_stopped(self, data: mqtt5.LifecycleStoppedData) -> None:
        self.stopped.set()

    def _on_message(self, data: mqtt5.PublishReceivedData) -> None:
        self.received.append(data.publish_packet.topic)

    def connect(self) -> tuple[bool, str]:
        self.connected.clear()
        self.failed.clear()
        self.stopped.clear()
        self.client = mqtt5_client_builder.mtls_from_path(
            cert_filepath=str(self.cert),
            pri_key_filepath=str(self.key),
            ca_filepath=str(self.cfg.root_ca),
            endpoint=self.cfg.endpoint,
            port=8883,
            client_id=self.client_id,
            session_behavior=mqtt5.ClientSessionBehaviorType.CLEAN,
            offline_queue_behavior=mqtt5.ClientOperationQueueBehaviorType.FAIL_ALL_ON_DISCONNECT,
            min_reconnect_delay_ms=self.reconnect_delay_ms,
            max_reconnect_delay_ms=self.reconnect_delay_ms + 2000,
            ack_timeout_sec=int(TIMEOUT),
            on_lifecycle_connection_success=self._on_success,
            on_lifecycle_connection_failure=self._on_failure,
            on_lifecycle_disconnection=self._on_disconnect,
            on_lifecycle_stopped=self._on_stopped,
            on_publish_received=self._on_message,
        )
        self.client.start()
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if self.connected.wait(0.1):
                return True, "CONNACK SUCCESS"
            if self.failed.is_set():
                detail = self.failure_detail  # stop() reports its own failure; keep the real one
                if not self.auto_reconnect:
                    self.stop()
                return False, detail
        self.stop()
        return False, "timed out waiting for CONNACK"

    def ensure_connected(self) -> None:
        """AWS may close the connection after a denied action; reconnect before the next test."""
        if self.client is not None and self.connected.wait(3):
            return
        self.stop()
        self.connect()

    def publish(self, topic: str, payload: dict[str, Any] | str) -> tuple[bool, str]:
        body = payload if isinstance(payload, str) else json.dumps(payload)
        try:
            assert self.client is not None
            future = self.client.publish(mqtt5.PublishPacket(topic=topic, payload=body.encode(), qos=mqtt5.QoS.AT_LEAST_ONCE))
            result: mqtt5.PublishCompletionData = future.result(TIMEOUT)
        except Exception as exc:  # noqa: BLE001 - any failure here means the broker did not accept it
            return False, f"{type(exc).__name__}: {exc}"
        code = result.puback.reason_code
        return code.value < 0x80, f"PUBACK {code.name}"

    def subscribe(self, topic_filter: str) -> tuple[bool, str]:
        try:
            assert self.client is not None
            future = self.client.subscribe(mqtt5.SubscribePacket(subscriptions=[mqtt5.Subscription(topic_filter=topic_filter, qos=mqtt5.QoS.AT_LEAST_ONCE)]))
            suback: mqtt5.SubackPacket = future.result(TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {exc}"
        code = suback.reason_codes[0]
        return code.value < 0x80, f"SUBACK {code.name}"

    def stop(self) -> None:
        if self.client is None:
            return
        try:
            self.client.stop(mqtt5.DisconnectPacket())
            self.stopped.wait(TIMEOUT)
        except Exception:  # noqa: BLE001 - already stopped
            pass
        self.client = None
        self.connected.clear()


def report(who: str, action: str, result: tuple[bool, str], board: Scoreboard | None = None, expect: str | None = None) -> bool:
    ok, detail = result
    (allowed if ok else blocked)(who, f"{action} -> {detail}")
    if board is not None and expect is not None:
        board.expect(f"{who}: {action}", expect, ok)
    return ok


def telemetry(thing: str, seq: int, base: float) -> dict[str, Any]:
    return {
        "deviceId": thing,
        "seq": seq,
        "temperature": round(base + random.uniform(-1.5, 1.5), 2),
        "humidity": round(random.uniform(35, 55), 1),
        "pressure": round(random.uniform(1005, 1020), 1),
        "sentAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ---------------------------------------------------------------- scenarios


def cmd_fleet(cfg: Config, args: argparse.Namespace) -> int:
    heading(f"Fleet: {len(cfg.sensors())} sensors, telemetry every {args.interval}s" + (f" for {args.duration}s" if args.duration else " (Ctrl+C to stop)"))
    stop = threading.Event()
    errors: list[str] = []

    def run(key: str, base: float) -> None:
        # Well-behaved devices back off before reconnecting. This also lets `cross-topic`
        # borrow a sensor's identity for a few seconds while the fleet is running.
        dev = Device.for_thing(cfg, key, auto_reconnect=True, reconnect_delay_ms=20000)
        thing = cfg.thing_names[key]
        attempt(thing, "connect with own certificate")
        if not report(thing, "connect", dev.connect()):
            errors.append(thing)
            return
        report(thing, f"subscribe sensors/{thing}/commands", dev.subscribe(f"sensors/{thing}/commands"))
        report(thing, "publish status online", dev.publish(f"sensors/{thing}/status", {"status": "online"}))
        seq = 0
        while not stop.is_set():
            seq += 1
            payload = telemetry(thing, seq, base)
            ok, detail = dev.publish(f"sensors/{thing}/telemetry", payload)
            if ok:
                allowed(thing, f"telemetry #{seq} T={payload['temperature']}C H={payload['humidity']}% P={payload['pressure']}hPa")
            elif not dev.connected.is_set():
                # e.g. another client (cross-topic demo) briefly took over this client ID
                info(thing, f"telemetry #{seq} skipped: offline ({dev.disconnects[-1] if dev.disconnects else 'disconnected'}), reconnecting")
            else:
                blocked(thing, f"telemetry #{seq} -> {detail}")
                errors.append(thing)
            stop.wait(args.interval)
        dev.publish(f"sensors/{thing}/status", {"status": "offline"})
        dev.stop()
        info(thing, "disconnected")

    threads = [threading.Thread(target=run, args=(k, 18 + 4 * i), daemon=True) for i, k in enumerate(cfg.sensors())]
    for t in threads:
        t.start()
        time.sleep(0.3)
    try:
        if args.duration:
            stop.wait(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    stop.set()
    for t in threads:
        t.join(TIMEOUT * 2)
    return 1 if errors else 0


def cmd_cross_topic(cfg: Config, args: argparse.Namespace) -> int:
    key = cfg.key(args.device)
    me = cfg.thing_names[key]
    victim_key = next(k for k in cfg.sensors() if k != key)
    victim = cfg.thing_names[victim_key]
    heading(f"Least privilege: {me} tries to use {victim}'s topics")
    board = Scoreboard()

    dev = Device.for_thing(cfg, key)
    attempt(me, "connect with own certificate")
    if not report(me, "connect", dev.connect(), board, "allowed"):
        board.report()
        return 1

    # Five denied actions in total (4 here + the impersonation below): one run stays under the
    # detector's "more than 5 auth failures in 5 minutes" rule, so a healthy sensor is not quarantined.
    checks = [
        ("publish", f"sensors/{me}/telemetry", "allowed"),
        ("publish", f"sensors/{victim}/telemetry", "blocked"),
        ("publish", f"$aws/things/{victim}/shadow/update", "blocked"),
        ("subscribe", f"sensors/{me}/commands", "allowed"),
        ("subscribe", f"sensors/{victim}/commands", "blocked"),
        ("subscribe", "sensors/#", "blocked"),
    ]
    for action, topic, expect in checks:
        dev.ensure_connected()
        attempt(me, f"{action} {topic}")
        if action == "publish":
            result = dev.publish(topic, telemetry(me, 1, 20.0))
        else:
            result = dev.subscribe(topic)
        report(me, f"{action} {topic}", result, board, expect)
    dev.stop()

    # Identity is bound to the certificate: my certificate cannot connect under another thing's name.
    imposter = Device.for_thing(cfg, key, client_id=victim, label=me)
    attempt(me, f"connect as client ID {victim} using my certificate")
    report(me, f"connect as {victim}", imposter.connect(), board, "blocked")
    imposter.stop()
    return 0 if board.report() else 1


def _self_signed(directory: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "iot-project-sensor-001")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "selfsigned.cert.pem", directory / "selfsigned.private.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert_path, key_path


def _tls_without_client_cert(cfg: Config) -> tuple[bool, str]:
    """Raw TLS + MQTT CONNECT with no client certificate at all."""
    context = ssl.create_default_context(cafile=str(cfg.root_ca))
    try:
        with socket.create_connection((cfg.endpoint, 8883), timeout=TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=cfg.endpoint) as tls:
                client_id = b"iot-project-sensor-001"
                body = b"\x00\x04MQTT\x04\x02\x00\x3c" + len(client_id).to_bytes(2, "big") + client_id
                tls.sendall(bytes([0x10, len(body)]) + body)
                reply = tls.recv(4)
                if len(reply) >= 4 and reply[0] == 0x20 and reply[3] == 0:
                    return True, "CONNACK accepted"
                return False, f"connection closed by AWS IoT (reply={reply.hex() or 'none'})"
    except (ssl.SSLError, OSError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def cmd_no_cert(cfg: Config, args: argparse.Namespace) -> int:
    heading("Authentication: devices without a valid AWS IoT certificate")
    board = Scoreboard()
    who = "unregistered-device"

    with tempfile.TemporaryDirectory() as tmp:
        cert, key = _self_signed(Path(tmp))
        attempt(who, "mutual TLS with a self-signed certificate, client ID iot-project-sensor-001")
        dev = Device(cfg, who, cert, key, "iot-project-sensor-001")
        report(who, "connect with self-signed certificate", dev.connect(), board, "blocked")
        dev.stop()

    attempt(who, "TLS with no client certificate at all, then MQTT CONNECT")
    report(who, "connect without client certificate", _tls_without_client_cert(cfg), board, "blocked")

    key = cfg.sensors()[0]
    other_key = Path(cfg.cert_files[cfg.sensors()[1]]["private_key"])
    attempt(who, f"{cfg.thing_names[key]}'s certificate with a different device's private key")
    try:
        mismatched = Device(cfg, who, Path(cfg.cert_files[key]["certificate"]), other_key, cfg.thing_names[key])
        result = mismatched.connect()
        mismatched.stop()
    except Exception as exc:  # noqa: BLE001 - the TLS stack may refuse the pair before connecting
        result = (False, f"{type(exc).__name__}: {exc}")
    report(who, "connect with stolen certificate but wrong key", result, board, "blocked")
    return 0 if board.report() else 1


def cmd_rogue(cfg: Config, args: argparse.Namespace) -> int:
    key = "rogue-001"
    me = cfg.thing_names[key]
    victim = cfg.thing_names[cfg.sensors()[0]]
    heading(f"Rogue device {me}: oversized payloads, forbidden topics, impersonation, reconnect storm")
    totals = {"denied actions": 0, "connects": 0, "disconnects": 0, "oversized": 0}

    dev = Device.for_thing(cfg, key)
    attempt(me, "connect with own certificate")
    ok, detail = dev.connect()
    report(me, "connect", (ok, detail))
    if not ok:
        info(me, "the rogue certificate is already blocked - it has been quarantined")
        return 0
    totals["connects"] += 1

    heading("1. Oversized messages on its own topic (allowed by policy, flagged by the detector)")
    for i in range(3):
        payload = {**telemetry(me, i, 25.0), "blob": "X" * 4096}
        report(me, f"publish {len(json.dumps(payload))} bytes to own telemetry", dev.publish(f"sensors/{me}/telemetry", payload))
        totals["oversized"] += 1

    heading("2. Forbidden topics")
    targets = [
        ("publish", f"sensors/{victim}/telemetry"),
        ("publish", f"$aws/things/{victim}/shadow/update"),
        ("publish", "factory/firmware/push"),
        ("subscribe", "#"),
        ("subscribe", f"sensors/{victim}/commands"),
    ]
    for round_ in range(args.rounds):
        for action, topic in targets:
            dev.ensure_connected()
            result = dev.publish(topic, {"cmd": "shutdown"}) if action == "publish" else dev.subscribe(topic)
            if not report(me, f"{action} {topic}", result):
                totals["denied actions"] += 1
    totals["connects"] += dev.connects - 1
    totals["disconnects"] += len(dev.disconnects)
    dev.stop()

    heading("3. Impersonation: rogue certificate claims to be another sensor")
    for _ in range(2):
        imp = Device.for_thing(cfg, key, client_id=victim, label=me)
        if not report(me, f"connect as {victim}", imp.connect()):
            totals["denied actions"] += 1
        imp.stop()

    heading(f"4. Reconnect storm ({args.reconnects} rapid connect/disconnect cycles)")
    for i in range(args.reconnects):
        storm = Device.for_thing(cfg, key)
        ok, detail = storm.connect()
        if ok:
            totals["connects"] += 1
            storm.stop()
            totals["disconnects"] += 1
            allowed(me, f"cycle {i + 1}: connected and dropped")
        else:
            blocked(me, f"cycle {i + 1}: {detail}")
        time.sleep(0.5)

    heading("Rogue activity generated")
    for name, count in totals.items():
        print(f"  {name:<16} {count}")
    print(
        "\n  Detector thresholds (per 5-minute window): auth failures > 5, connection attempts > 10,\n"
        "  disconnects > 5, message size > 1024 bytes. Expect an SNS alert and automatic quarantine\n"
        "  within a minute or two. Check with: python emulator.py status"
    )
    return 0


def cmd_stolen_cert(cfg: Config, args: argparse.Namespace) -> int:
    key = "rogue-001"
    thing = cfg.thing_names[key]
    heading(f"Stolen certificate: two clients use {thing}'s certificate at once for {args.duration}s")

    owner = Device.for_thing(cfg, key, label=f"{thing} (owner)", auto_reconnect=True)
    thief = Device.for_thing(cfg, key, label=f"{thing} (thief)", auto_reconnect=True)
    for dev in (owner, thief):
        attempt(dev.label, "connect with the same certificate and client ID")
        report(dev.label, "connect", dev.connect())
        time.sleep(1)

    info("both", "AWS IoT allows one session per client ID, so each connection kicks the other off")
    end = time.monotonic() + args.duration
    seen = {owner.label: 0, thief.label: 0}
    while time.monotonic() < end:
        for dev in (owner, thief):
            while seen[dev.label] < len(dev.disconnects):
                blocked(dev.label, f"disconnected by AWS: {dev.disconnects[seen[dev.label]]}")
                seen[dev.label] += 1
        time.sleep(0.5)
    for dev in (owner, thief):
        dev.stop()

    heading("Thief tries a different client ID with the stolen certificate")
    clone = Device.for_thing(cfg, key, client_id=f"{thing}-clone", label=f"{thing} (thief)")
    report(clone.label, f"connect as {thing}-clone", clone.connect())
    clone.stop()

    heading("Result")
    print(f"  owner: {owner.connects} connects, {len(owner.disconnects)} forced disconnects")
    print(f"  thief: {thief.connects} connects, {len(thief.disconnects)} forced disconnects")
    print("  The duplicate-client-ID churn trips the detector's connect/disconnect rules, and the daily\n"
          "  Device Defender audit reports DEVICE_CERTIFICATE_SHARED_CHECK / CONFLICTING_CLIENT_IDS_CHECK.")
    return 0


# ---------------------------------------------------------------- operations


def _boto(cfg: Config, service: str) -> Any:
    import boto3

    return boto3.client(service, region_name=cfg.region)


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    iot = _boto(cfg, "iot")
    ddb = _boto(cfg, "dynamodb")
    heading("Devices")
    since = int((time.time() - 600) * 1000)
    for key in sorted(cfg.thing_names):
        thing = cfg.thing_names[key]
        for arn in iot.list_thing_principals(thingName=thing)["principals"]:
            cert_id = arn.rsplit("/", 1)[-1]
            status = iot.describe_certificate(certificateId=cert_id)["certificateDescription"]["status"]
            policies = [p["policyName"] for p in iot.list_attached_policies(target=arn)["policies"]]
            recent = ddb.query(
                TableName=cfg.telemetry_table,
                KeyConditionExpression="deviceId = :d AND ts > :t",
                ExpressionAttributeValues={":d": {"S": thing}, ":t": {"N": str(since)}},
                Select="COUNT",
            )["Count"]
            color = Fore.GREEN if status == "ACTIVE" and cfg.quarantine_policy not in policies else Fore.RED
            print(f"  {color}{thing:<24}{Style.RESET_ALL} cert {cert_id[:10]}… {status:<9} policies={','.join(policies) or '-':<34} telemetry(10 min)={recent}")

    heading("Latest security events")
    items = ddb.scan(TableName=cfg.security_events_table)["Items"]
    items.sort(key=lambda i: i["timestamp"]["S"], reverse=True)
    for item in items[: args.limit]:
        kind = item.get("eventType", {}).get("S", "?")
        text = item.get("summary", item.get("reason", {})).get("S", "")
        color = Fore.RED if kind == "QUARANTINE" else Fore.YELLOW
        print(f"  {item['timestamp']['S']}  {color}{kind:<10}{Style.RESET_ALL} {item['deviceId']['S']:<24} {text}")
    if not items:
        print("  (none)")
    return 0


def cmd_quarantine(cfg: Config, args: argparse.Namespace) -> int:
    thing = cfg.thing_names[cfg.key(args.device)]
    function = cfg.lambda_functions["quarantine"]
    attempt("operator", f"invoke {function} for {thing}")
    response = _boto(cfg, "lambda").invoke(
        FunctionName=function,
        Payload=json.dumps({"thingName": thing, "reason": args.reason}).encode(),
    )
    body = json.loads(response["Payload"].read())
    print(json.dumps(body, indent=2))
    return 1 if response.get("FunctionError") else 0


def cmd_reset(cfg: Config, args: argparse.Namespace) -> int:
    """Undo a quarantine so the demo can be repeated."""
    thing = cfg.thing_names[cfg.key(args.device)]
    iot = _boto(cfg, "iot")
    for arn in iot.list_thing_principals(thingName=thing)["principals"]:
        cert_id = arn.rsplit("/", 1)[-1]
        attached = [p["policyName"] for p in iot.list_attached_policies(target=arn)["policies"]]
        if cfg.sensor_policy not in attached:
            iot.attach_policy(policyName=cfg.sensor_policy, target=arn)
        if cfg.quarantine_policy in attached:
            iot.detach_policy(policyName=cfg.quarantine_policy, target=arn)
        iot.update_certificate(certificateId=cert_id, newStatus="ACTIVE")
        allowed("operator", f"{thing}: cert {cert_id[:10]}… ACTIVE with {cfg.sensor_policy}")

    # Clear the detector's window counters too, or the next connect may re-trip a rule.
    ddb = _boto(cfg, "dynamodb")
    counters = ddb.query(
        TableName=cfg.device_metrics_table,
        KeyConditionExpression="deviceId = :d",
        ExpressionAttributeValues={":d": {"S": thing}},
        ProjectionExpression="deviceId, metricWindow",
    )["Items"]
    for item in counters:
        ddb.delete_item(TableName=cfg.device_metrics_table, Key=item)
    info("operator", f"{thing}: cleared {len(counters)} detector counter(s)")
    return 0


def _state_quarantine_policy() -> tuple[str, str] | None:
    """(region, name) of the quarantine policy in Terraform state, or None if it isn't there.

    Reads the state rather than the outputs: a destroy that failed part-way has already
    removed the outputs but may still hold the policy and a quarantined certificate.
    """
    try:
        raw = subprocess.run(
            ["terraform", f"-chdir={INFRA_DIR}", "show", "-json"],
            check=True, capture_output=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Could not read Terraform state: {exc}")
    resources = json.loads(raw).get("values", {}).get("root_module", {}).get("resources", [])
    for resource in resources:
        if resource["address"] == "aws_iot_policy.quarantine":
            values = resource["values"]
            return values["arn"].split(":")[3], values["name"]
    return None


def cmd_pre_destroy(_cfg: Config | None, args: argparse.Namespace) -> int:
    """Detach the quarantine policy from every certificate before `terraform destroy`.

    The quarantine Lambda attaches it outside Terraform, and AWS IoT refuses to delete a
    certificate or a policy while they are still attached to each other.
    """
    found = _state_quarantine_policy()
    if found is None:
        info("operator", "no quarantine policy in Terraform state - nothing to detach")
        return 0
    region, policy = found

    import boto3

    iot = boto3.client("iot", region_name=region)
    try:
        targets = [
            target
            for page in iot.get_paginator("list_targets_for_policy").paginate(policyName=policy)
            for target in page["targets"]
        ]
    except iot.exceptions.ResourceNotFoundException:
        info("operator", f"{policy} no longer exists in AWS - nothing to detach")
        return 0
    for target in targets:
        iot.detach_policy(policyName=policy, target=target)
        info("operator", f"detached {policy} from cert {target.rsplit('/', 1)[-1][:10]}…")
    if not targets:
        info("operator", f"{policy} is not attached to any certificate")
    return 0


def main() -> int:
    just_fix_windows_console()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("fleet", help="run all sensors sending telemetry")
    p.add_argument("--interval", type=int, default=60, help="seconds between readings (default 60)")
    p.add_argument("--duration", type=int, default=0, help="stop after N seconds (default: run until Ctrl+C)")
    p.set_defaults(func=cmd_fleet)

    p = sub.add_parser("cross-topic", help="a sensor tries to use another sensor's topics")
    p.add_argument("device", nargs="?", default="sensor-002")
    p.set_defaults(func=cmd_cross_topic)

    sub.add_parser("no-cert", help="connect without a valid certificate").set_defaults(func=cmd_no_cert)

    p = sub.add_parser("rogue", help="rogue-001 misbehaves to trigger detection")
    p.add_argument("--rounds", type=int, default=2, help="rounds of forbidden-topic attempts (5 each)")
    p.add_argument("--reconnects", type=int, default=12)
    p.set_defaults(func=cmd_rogue)

    p = sub.add_parser("stolen-cert", help="two clients share rogue-001's certificate")
    p.add_argument("--duration", type=int, default=60)
    p.set_defaults(func=cmd_stolen_cert)

    p = sub.add_parser("status", help="certificate status, policies, recent telemetry and security events")
    p.add_argument("--limit", type=int, default=10)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("quarantine", help="manually invoke the quarantine Lambda")
    p.add_argument("device", nargs="?", default="rogue-001")
    p.add_argument("--reason", default="manual quarantine from emulator")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("reset", help="undo a quarantine (re-activate certificate, restore sensor policy)")
    p.add_argument("device", nargs="?", default="rogue-001")
    p.set_defaults(func=cmd_reset)

    p = sub.add_parser("pre-destroy", help="detach the quarantine policy so terraform destroy can delete the certificates")
    p.set_defaults(func=cmd_pre_destroy, needs_config=False)

    args = parser.parse_args()
    return args.func(load_config() if getattr(args, "needs_config", True) else None, args)


if __name__ == "__main__":
    sys.exit(main())
