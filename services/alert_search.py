from data.json_reader import *


def search_alerts_by_source_ip(ip):
    alerts = read_json("security_alerts.json")

    alerts_list = []

    for alert in alerts:
        if alert is None:
            continue

        if alert ["event"] ["source.ip"].upper() == ip:
            alerts_list.append(alert)

    return alerts_list