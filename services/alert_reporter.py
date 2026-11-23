from services.alert_extractor import *
from services.alert_analyzer import *
from services.alert_search import *


def generate_alert_report():
    alerts = read_json("security_alerts.json")
    alerts_list = []

    for alert in alerts:
        if alert is None:
            continue

        rule = alert.get("rule") or {}
        event = alert.get("event") or {}
        evidence = alert.get("evidence") or {}

        alert_report = {
            "alert_id": rule.get("id"),
            "alert_name": rule.get("name"),
            "severity": rule.get("severity"),
            "risk_score": rule.get("risk_score"),
            "reason": evidence.get("reason"),
            "confidence": evidence.get("confidence"),
            "outcome": event.get("event.outcome"),
            "matched_pattern": evidence.get("matched_pattern")
        }
        alerts_list.append(alert_report)
    return alerts_list
