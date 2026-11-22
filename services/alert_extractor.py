import dataclasses

from data.json_reader import read_json


def extract_alerts_ids():
    data = read_json("security_alerts.json")

    for alert in data:
        rule = alert.get("rule") or {}
        alert_id = rule.get("id")

        print(alert_id)


def extract_alerts_names():
    data = read_json("security_alerts.json")

    for alert in data:
        rule = alert.get("rule") or {}
        alert_name = rule.get("name")

        print(alert_name)
