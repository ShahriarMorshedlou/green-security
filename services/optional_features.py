from data.json_reader import read_json


def detect_duplicate_alert():
    alert_security = read_json("security_alerts.json")
    duplicate_alert_list = []
    id_count = {}

    for alert in alert_security:
        if alert is None:
            continue

        rule = alert.get("rule") or {}
        rule_id = rule.get("id")

        if rule_id in id_count:
            id_count[rule_id] += 1
        else:
            id_count[rule_id] = 1

    for alert in alert_security:
        if alert is None:
            continue

        if id_count[rule_id] > 1:
            duplicate_alert_list.append(alert)

    if not duplicate_alert_list:
        print("No duplicate alert")


def get_risk_score(alert):
    rule = alert.get("rule") or {}
    return rule.get("risk_score") or 0


def sort_alerts_by_risk_score():
    alert_security = read_json("security_alerts.json")

    sorted_alerts = sorted(
        alert_security,
        key=get_risk_score,
        reverse=True
    )

    return sorted_alerts


def search_by_destination_ip(ip):
    alert_security = read_json("security_alerts.json")
    matching_alerts = []

    for alert in alert_security:
        if alert is None:
            continue

        event = alert.get("event") or {}
        destination_ip = event.get("destination.ip")

        if ip == destination_ip:
            matching_alerts.append(alert)

    return matching_alerts
