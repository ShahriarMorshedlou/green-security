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
