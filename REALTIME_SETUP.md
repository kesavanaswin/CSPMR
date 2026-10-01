# CSPM True Real-Time Upgrade

This extension keeps the repository's existing PolicyEngine, AnomalyDetector,
RiskEngine and MitigationEngine. It replaces the simulated boundaries with
live integrations.

## 1. Install

From the CSPM repository root:

    python -m venv .venv
    .venv\Scripts\activate

    pip install -r requirements.txt
    pip install -r requirements-realtime.txt

Install separately:
- Docker Desktop / Docker Engine
- Trivy
- Falco (Linux/Kubernetes recommended for runtime monitoring)
- kubectl if using Kubernetes
- OPA if you want the existing OPA/Rego path enabled

## 2. Copy the upgrade files

Copy:
- integrations/
- realtime_cspm.py
- admission_webhook.py
- dashboard_realtime.py
- deploy/
- config/realtime.env.example

into the repository root.

## 3. Docker + Trivy test

Verify:

    docker version
    trivy --version

Run the live CSPM:

    python realtime_cspm.py

The process watches Docker container lifecycle events and refreshes the
container configuration. New/changed images are scanned by Trivy.

Force rescans:

    python realtime_cspm.py --rescan

## 4. Falco

Configure Falco to emit JSON lines to the path configured by CSPM_FALCO_LOG.

Example environment variable:

Windows CMD:
    set CSPM_FALCO_LOG=C:\path\to\falco.json

PowerShell:
    $env:CSPM_FALCO_LOG="C:\path\to\falco.json"

Linux:
    export CSPM_FALCO_LOG=/var/log/falco/falco.json

Then:

    python realtime_cspm.py

Falco events cause the CSPM anomaly/risk pipeline to re-evaluate the affected
container.

## 5. Dashboard

In another terminal:

    streamlit run dashboard_realtime.py

The dashboard reads the generated CSPM JSON artifacts and refreshes
automatically.

## 6. Slack/webhook

Set the webhook as an environment variable.

Windows CMD:
    set CSPM_SLACK_WEBHOOK=https://hooks.slack.com/services/REDACTED

PowerShell:
    $env:CSPM_SLACK_WEBHOOK="https://hooks.slack.com/services/REDACTED"

Linux:
    export CSPM_SLACK_WEBHOOK="https://hooks.slack.com/services/REDACTED"

Do not put the real secret in Git.

## 7. Kubernetes admission

Install the Flask dependency and run:

    python admission_webhook.py

The production deployment should expose this endpoint through a Kubernetes
Service and TLS. Configure a ValidatingWebhookConfiguration to send
AdmissionReview requests to `/validate`.

Important: the example webhook intentionally evaluates configuration posture.
For production-grade admission, add image digest resolution and Trivy policy
checks before allowing an image.

## 8. End-to-end demonstration

Use a disposable local test environment.

1. Start the CSPM.
2. Start a test container.
3. Observe Docker lifecycle ingestion.
4. Observe Trivy scan.
5. Trigger a controlled Falco rule in the test container.
6. Observe the runtime event.
7. Observe anomaly detection.
8. Observe the unified risk score.
9. Observe the dashboard update.
10. For a Kubernetes test, submit a deliberately non-compliant test Pod and
    observe the AdmissionReview response.

## 9. Architecture

Docker/Kubernetes -> ingestion -> policy/vulnerability/runtime analysis ->
correlation -> unified risk -> dashboard/alerting/admission.

## 10. Safety defaults

Automatic container termination or deletion is intentionally NOT implemented
by this extension. Admission denial is the only automatic enforcement path.
This makes the PG demonstration reproducible and avoids destructive actions.
