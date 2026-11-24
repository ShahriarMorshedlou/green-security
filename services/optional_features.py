from data.json_reader import read_json

from services.alert_validation import (
    validate_sql_injection,
    validate_xss,
    validate_path_traversal,
    validate_ssrf,
    validate_login_brute_force,
    validate_directory_brute_force,
    validate_lfi,
    validate_command_injection,
    validate_executable_upload,
    validate_auth_bypass
)


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
def validate_alerts():
    alert_security = read_json("security_alerts.json")

    # (اسم حمله، تابع validator)
    validators = [
        ("SQL Injection", validate_sql_injection),
        ("XSS", validate_xss),
        ("Path Traversal", validate_path_traversal),
        ("SSRF", validate_ssrf),
        ("Login Brute Force", validate_login_brute_force),
        ("Directory Brute Force", validate_directory_brute_force),
        ("LFI", validate_lfi),
        ("Command Injection", validate_command_injection),
        ("Executable Upload", validate_executable_upload),
        ("Auth Bypass", validate_auth_bypass),
    ]

    result = {"MATCH": [], "MISMATCH": [], "INSUFFICIENT": []}

    for alert in alert_security:
        if alert is None:
            continue

        rule = alert.get("rule") or {}

        match_info = None
        mismatch_info = None
        insufficient_reason = None

        for name, validator in validators:
            status, reason = validator(alert)

            if status == "MATCH" and match_info is None:
                match_info = (name, reason)
            elif status == "MISMATCH" and mismatch_info is None:
                mismatch_info = (name, reason)
            elif status == "INSUFFICIENT" and reason is not None and insufficient_reason is None:
                insufficient_reason = reason

        # تصمیم نهایی
        if match_info is not None:
            final_status = "MATCH"
            attack_type, final_reason = match_info
        elif mismatch_info is not None:
            final_status = "MISMATCH"
            attack_type, final_reason = mismatch_info
        else:
            final_status = "INSUFFICIENT"
            attack_type = None
            final_reason = insufficient_reason or "نوع حمله از روی rule.logic شناسایی نشد"

        result[final_status].append({
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name"),
            "attack_type": attack_type,
            "reason": final_reason,
            "alert": alert,
        })

    return result