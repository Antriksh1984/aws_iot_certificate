# iot-project: per-device X.509 identity on AWS IoT Core

A cloud-only demo of certificate-based device security on AWS IoT Core. There is no hardware: a Python emulator plays five industrial sensors and one rogue device, each with its own AWS-issued X.509 certificate.

The demo shows that:

1. **Every device has its own certificate.** Without a valid one, a device can't connect.
2. **Least privilege applies.** A device can publish and subscribe only on its own topics.
3. **Good telemetry lands in DynamoDB.**
4. **A rogue device is detected and quarantined automatically.** An email alert is sent, the certificate gets a deny-all policy and is set INACTIVE, and the other sensors keep working.
5. **A weekly check reports certificates close to expiry.**

Everything is Terraform-managed in `ap-south-1` and removed with `make destroy`.

> **Note:** AWS closed Device Defender *Detect* to new customers on 31 Aug 2026. This project uses its own **detector Lambda**, which applies the same rules and sends alerts in the Device Defender violation format. The real Detect profile is kept behind `enable_device_defender_detect` (default `false`). Device Defender **Audit** is enabled.

## Components

| Piece | What it does |
|---|---|
| **Things and certificates** | Six things (`sensor-001`…`005`, `rogue-001`) in group `iot-project-sensors`, each with its own certificate attached to the sensor policy. |
| **Sensor policy** | Connect only with your own thing name as client ID; publish only to `sensors/<self>/telemetry` and `/status`; subscribe only to `/commands` and `/config`; own shadow only. |
| **Quarantine policy** | Explicit `Deny iot:*`, which overrides any allow. |
| **Telemetry path** | IoT rule on `sensors/+/telemetry` → `telemetry-processor` Lambda → `iot-project-telemetry` table (30-day TTL). |
| **Detector** | Per device, in 5-minute windows: auth failures > 5, connection attempts > 10, disconnects > 5, any message > 1024 bytes. Events are charged to the certificate's owner, not the claimed client ID. A breach sends a violation to SNS. |
| **Audit** | Daily check for expiring, shared or revoked certificates, overly permissive policies, disabled logging and conflicting client IDs. |
| **Quarantine** | Triggered by `in-alarm` alerts. Attaches the quarantine policy, detaches all others, sets the certificate INACTIVE and logs to `iot-project-security-events`. Can also be run manually. |
| **Certificate expiry** | EventBridge runs it every 7 days and emails any certificates expiring within 30 days. |
| **Monitoring** | CloudWatch dashboard and alarms, IoT logs at `WARN`, and a $5/month budget alert. |

## Deploy

Needs Terraform ≥ 1.6, Python 3.12 and AWS admin credentials.

```bash
cp infra/terraform.tfvars.example infra/terraform.tfvars   # set alert_email
make init
make deploy
```

Confirm the SNS subscription email, or no alerts will arrive. Quarantine still works without it.

## Demo

Run from `emulator/`:

| Step | Command | Result |
|---|---|---|
| Healthy fleet | `python emulator.py fleet` | Five sensors connect and publish; `status` shows rows in DynamoDB. |
| Least privilege | `python emulator.py cross-topic sensor-002` | Own topic succeeds; other devices' topics and client IDs are `NOT_AUTHORIZED`. |
| Authentication | `python emulator.py no-cert` | Self-signed, missing and mismatched-key certificates fail at the TLS handshake. |
| Rogue device | `python emulator.py rogue` | Oversized payloads, forbidden topics, impersonation and a reconnect storm. Quarantined about 6 s after the first violation, with an email alert. |
| Stolen certificate | `python emulator.py stolen-cert` | Two clients sharing one certificate keep kicking each other off; the detector quarantines it. |
| Fleet unaffected | `python emulator.py status` | The five sensors stay ACTIVE. |
| Reset | `python emulator.py reset rogue-001` | Re-activates the certificate and clears its counters. |

Shortcuts: `make demo-fleet`, `make demo-attack`, `make quarantine`, `make reset`, `make status`.

**Detection notes:** auth failures come from IoT logs, and connects and disconnects from lifecycle events. Denied subscribes aren't logged by AWS, so only the emulator shows them. Quarantine runs within about 1 s of an alert, and AWS IoT takes up to about 20 s to start refusing the certificate.

## Live dashboard (Grafana)

A local Grafana dashboard (`localhost:3000`, refreshes every 10 s) shows fleet telemetry, blocked attacks, the violation → quarantine timeline, and Lambda health. It reads CloudWatch through a read-only role.

```bash
powershell -File grafana/install.ps1   # one-time
powershell -File grafana/start.ps1
```

## Cost

Well under **$1/month** idle and a few cents per demo run. AWS Config, Security Hub, ML Detect and customer-managed KMS keys are deliberately not used.

## Teardown

```bash
make destroy
```

This first detaches the quarantine policy (attached outside Terraform), then deletes everything, including the local `certs/` files.

## Security notes

- Private keys are in Terraform state and `certs/` (both gitignored). That's fine for a lab but not for production, where devices should generate their own keys or use fleet provisioning.
- Each Lambda has its own least-privilege role. There are no `*FullAccess` policies.

## Repository layout

```
infra/      Terraform configuration
lambdas/    telemetry_processor, detector, quarantine, cert_expiry, tests/
emulator/   emulator.py (MQTT 5 over mutual TLS)
grafana/    dashboard setup and build script
.github/    CI: terraform validate, tflint, checkov, Lambda tests
```
