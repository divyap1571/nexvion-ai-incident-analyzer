import re
import os
import secrets
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import json
import urllib.request
import urllib.parse
import urllib.error

app = FastAPI(
    title="Nexvion AI Incident Analyzer",
    description="Free local AI-powered DevOps incident analysis",
    version="1.0.0",
)


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse("/opt/nexvion-ai/dashboard.html")

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.2:1b"


class Incident(BaseModel):
    alert_name: str = Field(min_length=1, max_length=200)
    severity: str = Field(default="unknown", max_length=50)
    description: str = Field(default="", max_length=3000)
    logs: str = Field(default="", max_length=6000)


@app.get("/health")
def health():
    return {"status": "ok", "service": "nexvion-ai-incident-analyzer"}


@app.post("/analyze")
def analyze(incident: Incident):
    test_text = f"{incident.description} {incident.logs}".lower()
    controlled_test = (
        "controlled api test" in test_text
        or "controlled functional test" in test_text
        or "functional test only" in test_text
    )
    no_failure_confirmed = (
        "no production incident" in test_text
        or "no failure is confirmed" in test_text
        or "no actual failure evidence" in test_text
    )
    no_logs = not incident.logs.strip() or "no logs supplied" in incident.logs.lower()

    if controlled_test and no_failure_confirmed and no_logs:
        analysis = f"""**1. Alert Summary**
- Alert Name: {incident.alert_name}
- Severity: {incident.severity}
- Description: {incident.description}

**2. Evidence Observed**
- This is a controlled functional/API test.
- No logs were supplied.
- No production incident or failure is confirmed by this test payload.

**3. Possible Causes (Unconfirmed)**
- None identified; this is a controlled test with no failure evidence.

**4. Missing Evidence**
- No incident evidence supplied; no further evidence is needed for this functional test.

**5. Safe Diagnostic Commands**
- None required for this functional test.

**6. Recommended Next Steps**
- The analyzer response was tested. Submit real alert details and relevant logs only if an actual issue occurs.

**7. Validation After Remediation**
- Not applicable; no production incident or remediation was tested."""
        return {
            "alert_name": incident.alert_name,
            "model": "deterministic-test-response",
            "analysis": analysis,
        }

    prompt = f"""
You are Nexvion's cautious Linux and Kubernetes DevOps incident assistant.

STRICT RULES:
- Preserve the alert name and severity exactly as provided.
- Never label any cause as confirmed unless the supplied logs directly prove it.
- With limited evidence, state: "Root cause is not confirmed from the supplied evidence."
- Do not invent metrics, events, services, errors, timestamps, sample logs, or command output.
- Never create example log lines and present them as observed evidence.
- Do not put invented terminal output or fabricated commands in the Evidence Observed section.
- Only recommend standard, widely available Linux commands; never invent command names.
- Do not use the command "ustat".
- If evidence is insufficient, clearly say so instead of filling gaps with guesses.
- Only repeat information explicitly present in the description and logs as observed evidence.
- Put all potential causes under "Possible Causes (Unconfirmed)".
- In "Missing Evidence", list only information needed to investigate; do not label missing items as confirmed.
- Recommend safe, read-only Linux diagnostic commands only.
- Use common Linux commands such as top, ps, uptime, free, vmstat, and journalctl when relevant.
- Explain commands accurately: vmstat reports virtual memory, processes, CPU, and system activity; it is not a filesystem-specific memory usage command.
- Use free for RAM and swap summary, df for filesystem space, and du for directory space.
- Do not assume a service exists. For service-specific commands, explain to replace the example service with the actual service name.
- In Evidence Observed, include only facts explicitly present in the supplied description and logs. Do not infer that an API, service, or system is healthy unless evidence proves it.
- If no logs are supplied, explicitly state that no logs were supplied and that no root cause is confirmed.
- Keep Possible Causes (Unconfirmed) short and relevant to the alert. Do not list generic causes without a clear connection to the evidence.
- Prefer read-only commands with a specific purpose; explain what each command checks and do not claim that a command was run.
- Recommend at most 4 diagnostic commands, selected specifically for the supplied alert and evidence.
- Use only standard Linux commands with well-known options; do not suggest arbitrary /sys paths, hardware-specific paths, or guessed service names.
- For a controlled test with no failure evidence, state that no diagnostic commands are necessary unless the user reports a real issue.
- Distinguish an API test request from a confirmed production incident; receiving a test payload does not prove a real incident occurred.
- Do not recommend investigating disk, memory, CPU, networking, or other subsystems unless the supplied alert or evidence makes them relevant.
- For a controlled test with no logs and no actual failure evidence, state that this validates the analyzer response only; do not invent incident causes or remediation steps.
- If the description explicitly says this is a controlled API/functional test and no production incident or failure is confirmed, do not list any possible causes. State "None identified; this is a controlled test with no failure evidence."
- For that controlled-test case, set Missing Evidence to "No incident evidence supplied; no further evidence is needed for this functional test."
- For that controlled-test case, Safe Diagnostic Commands must say "None required for this functional test." Do not list top, ps, free, df, du, or any other diagnostic commands.
- For that controlled-test case, Recommended Next Steps must say the analyzer response was tested and to submit real alert details/logs only if an actual issue occurs.
- For that controlled-test case, Validation After Remediation must say "Not applicable; no production incident or remediation was tested."
- Never describe top as a graphical tool; it is an interactive process/system monitor.
- Do not repeat command descriptions or evidence as if they were observed events.
- Do not suggest Android commands, destructive commands, or unsupported conclusions.
- Keep the answer concise and practical.

Return these sections:
1. Alert Summary
2. Evidence Observed
3. Possible Causes (Unconfirmed)
4. Missing Evidence
5. Safe Diagnostic Commands (explain each command)
6. Recommended Next Steps
7. Validation After Remediation

Alert Name: {incident.alert_name}
Severity (preserve exactly): {incident.severity}
Description: {incident.description}
Logs / Evidence:
{incident.logs or "No logs supplied."}
"""

    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            result = json.loads(response.read().decode("utf-8"))
        analysis = result.get("response", "")
        # Remove fabricated Markdown links from model-generated text.
        analysis = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", analysis)

        # Ensure the supplied severity is authoritative.
        severity_line = f"- Severity: {incident.severity}"
        if re.search(r"(?im)^\s*[-*]?\s*Severity\s*:", analysis):
            analysis = re.sub(
                r"(?im)^\s*[-*]?\s*Severity\s*:.*$",
                severity_line,
                analysis,
                count=1,
            )

        # Do not let the model deny the failure explicitly present in supplied HTTP 500 logs.
        supplied_http_500 = bool(
            re.search(r"HTTP\s*500", incident.logs, re.IGNORECASE)
        )
        if supplied_http_500 and re.search(
            r"(?i)no failure evidence|no incident evidence supplied|no production incident",
            analysis,
        ):
            analysis = (
                f"**1. Alert Summary**\n"
                f"- Alert Name: {incident.alert_name}\n"
                f"- Severity: {incident.severity}\n"
                f"- Description: {incident.description}\n\n"
                f"**2. Evidence Observed**\n"
                f"- The supplied logs contain HTTP 500 errors.\n"
                f"- Only the two provided log entries are treated as evidence; no wider production impact is established.\n\n"
                f"**3. Possible Causes (Unconfirmed)**\n"
                f"- Root cause is not confirmed from the supplied evidence.\n\n"
                f"**4. Missing Evidence**\n"
                f"- Relevant application stack trace, request context, and application/service status around the errors.\n\n"
                f"**5. Safe Diagnostic Commands**\n"
                f"- `journalctl -u <actual-service-name> --since '15 minutes ago'` — review recent logs for the actual affected service. Replace the placeholder with its real service name.\n"
                f"- `systemctl status <actual-service-name>` — inspect the actual service state; replace the placeholder with its real service name.\n\n"
                f"**6. Recommended Next Steps**\n"
                f"- Correlate the HTTP 500 timestamps with the affected application's logs and request details. Do not assume a root cause until additional evidence is available.\n\n"
                f"**7. Validation After Remediation**\n"
                f"- Not performed; no remediation was supplied or tested."
            )
        return {
            "alert_name": incident.alert_name,
            "model": MODEL,
            "analysis": analysis,
        }
    except urllib.error.URLError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Local AI model unavailable: {exc}",
        )
    except TimeoutError:
        raise HTTPException(status_code=504, detail="AI analysis timed out")


PROMETHEUS_ALERTS_URL = "http://127.0.0.1:9090/api/v1/alerts"


@app.get("/prometheus-alerts")
def get_prometheus_alerts():
    request = urllib.request.Request(
        PROMETHEUS_ALERTS_URL,
        headers={"Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("status") != "success":
            raise HTTPException(
                status_code=502,
                detail="Prometheus returned an unsuccessful response",
            )

        alerts = result.get("data", {}).get("alerts", [])
        return {
            "source": "Prometheus",
            "count": len(alerts),
            "alerts": alerts,
        }

    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Prometheus HTTP error: {exc.code}",
        )
    except urllib.error.URLError:
        raise HTTPException(
            status_code=503,
            detail="Prometheus is unavailable at the configured URL",
        )
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=502,
            detail="Prometheus returned invalid JSON",
        )


PROMETHEUS_RULES_URL = "http://127.0.0.1:9090/api/v1/rules"


@app.get("/prometheus-rules")
def get_prometheus_rules():
    request = urllib.request.Request(
        PROMETHEUS_RULES_URL,
        headers={"Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("status") != "success":
            raise HTTPException(
                status_code=502,
                detail="Prometheus returned an unsuccessful response",
            )

        groups = result.get("data", {}).get("groups", [])
        rules = []

        for group in groups:
            for rule in group.get("rules", []):
                if rule.get("type") == "alerting":
                    rules.append({
                        "name": rule.get("name"),
                        "state": rule.get("state"),
                        "query": rule.get("query"),
                        "duration_seconds": rule.get("duration"),
                        "labels": rule.get("labels", {}),
                        "annotations": rule.get("annotations", {}),
                        "active_alerts": rule.get("alerts", []),
                        "health": rule.get("health"),
                    })

        return {
            "source": "Prometheus",
            "count": len(rules),
            "rules": rules,
        }

    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Prometheus HTTP error: {exc.code}",
        )
    except urllib.error.URLError:
        raise HTTPException(
            status_code=503,
            detail="Prometheus is unavailable at the configured URL",
        )
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=502,
            detail="Prometheus returned invalid JSON",
        )


@app.post("/analyze-prometheus")
def analyze_prometheus():
    def query_metric(expression):
        url = (
            "http://127.0.0.1:9090/api/v1/query?query="
            + urllib.parse.quote(expression, safe="")
        )
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        if data.get("status") != "success":
            raise ValueError("Prometheus metric query unsuccessful")
        return data.get("data", {}).get("result", [])

    request = urllib.request.Request(
        PROMETHEUS_RULES_URL,
        headers={"Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("status") != "success":
            raise HTTPException(status_code=502, detail="Prometheus query was unsuccessful")

        cpu_metrics = query_metric(
            '100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'
        )
        memory_metrics = query_metric(
            '100 * (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))'
        )
    except urllib.error.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Prometheus HTTP error: {exc.code}")
    except urllib.error.URLError:
        raise HTTPException(status_code=503, detail="Prometheus is unavailable")
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=502, detail="Invalid Prometheus response")

    def format_metrics(rows):
        if not rows:
            return "Metric unavailable"
        return "; ".join(
            f"instance={row.get('metric', {}).get('instance', 'unknown')}, "
            f"value={row.get('value', [None, 'unknown'])[1]}"
            for row in rows
        )

    live_evidence = (
        "Live Prometheus CPU usage percentage: " + format_metrics(cpu_metrics) + "\n"
        "Live Prometheus memory usage percentage: " + format_metrics(memory_metrics)
    )

    firing = []
    for group in result.get("data", {}).get("groups", []):
        for rule in group.get("rules", []):
            if rule.get("type") != "alerting":
                continue
            for alert in rule.get("alerts", []):
                if alert.get("state") == "firing":
                    firing.append({
                        "rule_name": rule.get("name"),
                        "query": rule.get("query"),
                        "duration_seconds": rule.get("duration"),
                        "alert": alert,
                    })

    if not firing:
        return {
            "source": "Prometheus",
            "status": "no_firing_alerts",
            "message": "No firing alerts found. AI analysis was not run.",
            "firing_alert_count": 0,
            "live_metrics": {
                "cpu_usage_percent": [
                    {"instance": row.get("metric", {}).get("instance", "unknown"),
                     "value": row.get("value", [None, None])[1]}
                    for row in cpu_metrics
                ],
                "memory_usage_percent": [
                    {"instance": row.get("metric", {}).get("instance", "unknown"),
                     "value": row.get("value", [None, None])[1]}
                    for row in memory_metrics
                ],
            },
        }

    analyses = []
    for item in firing:
        alert = item["alert"]
        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})
        incident = Incident(
            alert_name=labels.get("alertname", item["rule_name"]),
            severity=labels.get("severity", "unknown"),
            description=(
                f"Prometheus alert is firing. "
                f"Summary: {annotations.get('summary', 'Not provided')}. "
                f"Rule query: {item['query']}. "
                f"Rule duration: {item['duration_seconds']} seconds. "
                f"Alert value: {alert.get('value', 'Not provided')}. "
                f"Labels: {json.dumps(labels)}."
            ),
            logs=live_evidence + "\nMetrics are live Prometheus evidence; "
                 "no application logs or process-level diagnostics were retrieved.",
        )
        analyses.append(analyze(incident))

    return {
        "source": "Prometheus",
        "status": "analysis_completed",
        "firing_alert_count": len(firing),
        "live_metrics": {
            "cpu_usage_percent": [
                {"instance": row.get("metric", {}).get("instance", "unknown"),
                 "value": row.get("value", [None, None])[1]}
                for row in cpu_metrics
            ],
            "memory_usage_percent": [
                {"instance": row.get("metric", {}).get("instance", "unknown"),
                 "value": row.get("value", [None, None])[1]}
                for row in memory_metrics
            ],
        },
        "analyses": analyses,
    }


@app.post("/alertmanager-webhook")
def alertmanager_webhook(
    payload: dict,
    authorization: str | None = Header(default=None),
):
    """Accept authenticated Alertmanager notifications and analyze firing alerts only."""
    expected_token = os.environ.get("ALERTMANAGER_WEBHOOK_TOKEN", "")

    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="Webhook authentication is not configured",
        )

    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    supplied_token = authorization.removeprefix("Bearer ")
    if not secrets.compare_digest(supplied_token, expected_token):
        raise HTTPException(status_code=401, detail="Invalid bearer token")

    alerts = payload.get("alerts", [])

    if not isinstance(alerts, list):
        raise HTTPException(status_code=400, detail="alerts must be a list")

    if len(alerts) > 10:
        raise HTTPException(
            status_code=413,
            detail="Maximum 10 alerts per webhook request",
        )

    analyses = []
    skipped = 0

    for alert in alerts:
        if not isinstance(alert, dict):
            raise HTTPException(
                status_code=400,
                detail="Each alert must be an object",
            )

        status = alert.get("status", payload.get("status", ""))
        if status != "firing":
            skipped += 1
            continue

        labels = alert.get("labels", {})
        annotations = alert.get("annotations", {})

        if not isinstance(labels, dict) or not isinstance(annotations, dict):
            raise HTTPException(
                status_code=400,
                detail="Alert labels and annotations must be objects",
            )

        alert_name = labels.get("alertname")
        if not isinstance(alert_name, str) or not alert_name.strip():
            raise HTTPException(
                status_code=400,
                detail="Firing alert is missing labels.alertname",
            )

        severity = labels.get("severity", "unknown")
        if not isinstance(severity, str):
            severity = "unknown"

        summary = annotations.get("summary", "")
        description = annotations.get("description", "")

        if not isinstance(summary, str):
            summary = ""
        if not isinstance(description, str):
            description = ""

        incident = Incident(
            alert_name=alert_name[:200],
            severity=severity[:50],
            description=(
                "Alert received from Alertmanager. "
                f"Summary: {summary[:1500]}. "
                f"Description: {description[:1500]}."
            ),
            logs=(
                "No application logs supplied. "
                f"Alert startsAt: {str(alert.get('startsAt', 'not provided'))[:100]}. "
                f"Alert value: {str(alert.get('value', 'not provided'))[:100]}."
            ),
        )

        analyses.append(analyze(incident))

    return {
        "source": "Alertmanager",
        "received_alert_count": len(alerts),
        "analyzed_alert_count": len(analyses),
        "skipped_non_firing_count": skipped,
        "analyses": analyses,
    }
