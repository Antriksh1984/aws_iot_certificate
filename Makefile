# IoT certificate security demo. Requires: terraform >= 1.6, python 3.12, AWS credentials.
# Windows: run from Git Bash (make via `winget install ezwinports.make`) or copy the commands.

TF        := terraform -chdir=infra
VENV      := .venv
ifeq ($(OS),Windows_NT)
PY        := $(VENV)/Scripts/python.exe
else
PY        := $(VENV)/bin/python
endif
EMULATOR  := cd emulator && ../$(PY) emulator.py
DEVICE    ?= rogue-001
REASON    ?= manual quarantine (make quarantine)

.PHONY: init deploy test demo-fleet demo-attack quarantine reset status grafana-install grafana destroy

init: ## Create the Python venv and initialise Terraform
	python -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r emulator/requirements.txt -r lambdas/requirements-dev.txt
	$(TF) init

deploy: ## Validate and apply the stack (needs infra/terraform.tfvars with alert_email)
	$(TF) fmt -check -recursive
	$(TF) validate
	$(TF) apply -auto-approve

test: ## Lambda unit tests
	$(PY) -m pytest lambdas/tests -q

demo-fleet: ## Five sensors publishing telemetry every 60 s (Ctrl+C to stop)
	$(EMULATOR) fleet

demo-attack: ## Least-privilege, authentication, rogue and stolen-certificate scenarios
	$(EMULATOR) cross-topic sensor-002
	$(EMULATOR) no-cert
	$(EMULATOR) rogue
	$(EMULATOR) reset rogue-001
	$(EMULATOR) stolen-cert

quarantine: ## Manually quarantine DEVICE (default rogue-001)
	$(EMULATOR) quarantine $(DEVICE) --reason "$(REASON)"

reset: ## Undo the quarantine of DEVICE so the demo can be repeated
	$(EMULATOR) reset $(DEVICE)

status: ## Certificate status, policies, recent telemetry and security events
	$(EMULATOR) status

grafana-install: ## Download portable Grafana OSS into tools/grafana (Windows)
	powershell -NoProfile -ExecutionPolicy Bypass -File grafana/install.ps1

grafana: ## Live dashboard at http://localhost:3000 (Ctrl+C to stop)
	powershell -NoProfile -ExecutionPolicy Bypass -File grafana/start.ps1

destroy: ## Remove every resource (certificates and keys included, even quarantined ones)
	$(EMULATOR) pre-destroy
	$(TF) destroy -auto-approve
