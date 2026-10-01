## True Real-Time Mode

The original repository's `--stream` mode demonstrates streaming by replaying
or tailing JSON telemetry. The upgrade in this folder connects the same
analysis/risk pipeline to live Docker lifecycle events, Trivy image scanning,
Falco JSON runtime alerts, real webhook delivery, a live Streamlit dashboard,
and a Kubernetes AdmissionReview endpoint.

Run:

    python realtime_cspm.py

Dashboard:

    streamlit run dashboard_realtime.py

See `REALTIME_SETUP.md` for the complete setup and PG-project demonstration.
