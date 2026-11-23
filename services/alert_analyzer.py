from services.alert_extractor import *


def number_of_each_severity_level():
    alerts = extract_alerts_severity()

    severity_levels = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for alert in alerts:
        if alert is None:
            continue
        severity = alert.strip().upper()
        if severity == "CRITICAL":
            severity_levels["CRITICAL"] += 1
        elif severity == "HIGH":
            severity_levels["HIGH"] += 1
        elif severity == "MEDIUM":
            severity_levels["MEDIUM"] += 1
        elif severity == "LOW":
            severity_levels["LOW"] += 1

    return severity_levels


def find_highest_risk_score():
    alerts = read_json("security_alerts.json")

    highest_score = None
    highest_alert = None

    for alert in alerts:
        if alert is None:
            continue

        rule = alert.get("rule") or {}
        risk_score = rule.get("risk_score")

        if risk_score is None:
            continue

        if highest_score is None or risk_score > highest_score:
            highest_score = risk_score
            highest_alert = alert

    return highest_alert




def risk_score_average():
    risk_scores = extract_alerts_risk_score()
    total = 0
    valid_count = 0

    for alter in risk_scores:
        if alter is None:
            continue
        total += alter
        valid_count += 1
    if valid_count == 0:
        return 0

    average_risk_score = total / valid_count

    return average_risk_score

def get_high_and_critical_alerts():
    extract_all_alerts = read_json("security_alerts.json")

    high_and_critical_alerts = []

    for alert in extract_all_alerts:
        if alert is None:
            continue

        rule = alert.get("rule") or {}
        severity = rule.get("severity")

        if severity is None:
            continue

        severity = severity.upper()

        if severity == "HIGH" or severity == "CRITICAL":
            high_and_critical_alerts.append(alert)

    return high_and_critical_alerts

