"""AWS Lambda handler for scheduled model re-scanning.

Reads a list of approved models, runs the lightweight scan on each, writes a
JSON report to S3, and publishes an SNS alert if any model has a HIGH/CRITICAL
finding. S3/SNS are used only when their environment variables are set, so the
same handler runs locally without AWS.
"""

import json
import os
from datetime import datetime, timezone

from aisentinel.core import scan_model_lightweight

ALERT_SEVERITIES = {"HIGH", "CRITICAL"}


def _load_model_list() -> list[str]:
    env_models = os.environ.get("MODELS")
    if env_models:
        return [m.strip() for m in env_models.split(",") if m.strip()]
    return ["distilbert-base-uncased", "gpt2"]


def scan_all(models: list[str]) -> dict:
    results = []
    alerts = []
    for model in models:
        res = scan_model_lightweight(model)
        results.append(res)
        worst = res.get("worst_severity", "INFO")
        if res.get("ok") and worst in ALERT_SEVERITIES:
            alerts.append({"model": model, "worst_severity": worst})
    return {"scanned": len(results), "alerts": alerts, "results": results}


def _write_report_to_s3(summary: dict) -> str | None:
    """Write the full report to S3 if REPORT_BUCKET is configured."""
    bucket = os.environ.get("REPORT_BUCKET")
    if not bucket:
        return None
    import boto3
    key = f"reports/{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')}.json"
    boto3.client("s3").put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(summary, indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    return f"s3://{bucket}/{key}"


def _publish_alert(summary: dict) -> bool:
    """Publish an SNS alert if there are alerts and ALERT_TOPIC_ARN is set."""
    topic = os.environ.get("ALERT_TOPIC_ARN")
    if not topic or not summary["alerts"]:
        return False
    import boto3
    lines = [f"- {a['model']}: {a['worst_severity']}" for a in summary["alerts"]]
    message = (
        "AI-Sentinel scheduled scan found models with HIGH/CRITICAL findings:\n\n"
        + "\n".join(lines)
        + f"\n\nTotal scanned: {summary['scanned']}"
    )
    boto3.client("sns").publish(
        TopicArn=topic,
        Subject="AI-Sentinel: model risk detected",
        Message=message,
    )
    return True


def handler(event, context):
    models = _load_model_list()
    summary = scan_all(models)

    report_location = _write_report_to_s3(summary)
    alerted = _publish_alert(summary)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "scanned": summary["scanned"],
            "alert_count": len(summary["alerts"]),
            "alerts": summary["alerts"],
            "report": report_location,
            "alerted": alerted,
        }),
    }