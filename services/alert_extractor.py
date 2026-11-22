from data.json_reader import read_json


def extract_alerts_ids():
    data = read_json("security_alerts.json")
    alert_ids = []

    for alert in data:
        rule = alert.get("rule") or {}
        alert_id = rule.get("id")
        alert_ids.append(alert_id)

    return alert_ids


def extract_alerts_names():
    data = read_json("security_alerts.json")
    alert_names = []

    for alert in data:
        rule = alert.get("rule") or {}
        alert_name = rule.get("name")
        alert_names.append(alert_name)

    return alert_names


def extract_alerts_severity():
    data = read_json("security_alerts.json")
    alert_severities = []

    for alert in data:
        rule = alert.get("rule") or {}
        alert_severity = rule.get("severity")
        alert_severities.append(alert_severity)

    return alert_severities


def extract_alerts_risk_score():
    data = read_json("security_alerts.json")
    alert_risk_scores = []

    for alert in data:
        rule = alert.get("rule") or {}
        alert_risk_score = rule.get("risk_score")
        alert_risk_scores.append(alert_risk_score)

    return alert_risk_scores


def extract_alerts_source_ip_and_timestamp():
    data = read_json("security_alerts.json")
    alert_events = []

    for alert in data:
        event = alert.get("event") or {}

        source_ip = event.get("source.ip")
        timestamp = event.get("@timestamp")

        alert_events.append({
            "source_ip": source_ip,
            "timestamp": timestamp
        })

    return alert_events

def extract_alerts_count():
    data = read_json("security_alerts.json")
    alert_count = 0
    for alert in data:
        alert_count += 1

    return alert_count
