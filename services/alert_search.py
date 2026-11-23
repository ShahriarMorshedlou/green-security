from data.json_reader import *


def search_alerts_by_source_ip(ip):
    alerts = read_json("security_alerts.json")

    alerts_list = []

    for alert in alerts:
        if alert is None:
            continue

        if alert["event"]["source.ip"].casefold() == ip.casefold():
            alerts_list.append(alert)

    return alerts_list


def search_alerts_by_name_or_part_of_name(name):
    alerts = read_json("security_alerts.json")

    alerts_list = []

    for alert in alerts:
        if alert is None:
            continue

        alert_name = alert["rule"]["name"]
        if name.casefold() in alert_name.casefold():
            alerts_list.append(alert)

    return alerts_list
