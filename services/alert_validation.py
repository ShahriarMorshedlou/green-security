def validate_sql_injection(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify SQL Injection from rule.logic

    sql_logic_keywords = [
        "sql injection",
        "query parameters",
    ]

    if not all(keyword in logic for keyword in sql_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check SQL Injection patterns in matched_pattern

    sql_evidence_patterns = [
        "or 1=1",
        "union select",
        "select",
        "insert",
        "drop",
        "delete",
        "sleep(",
        "benchmark("
    ]

    if any(pattern in matched_pattern for pattern in sql_evidence_patterns):
        return "MATCH"

    # 4. Check SQL Injection keywords in reason

    sql_reason_keywords = [
        "boolean expression",
        "sql-like",
        "database query",
        "sql injection"
    ]

    if any(keyword in reason for keyword in sql_reason_keywords):
        return "MATCH"

    return "MISMATCH"

# def validate_xss():
# def validate_path_traversal():
# def validate_lfi():
# def validate_ssrf():
# def validate_login_brute_force():
# def validate_directory_brute_force():
# def validate_command_injection():
# def validate_executable_upload():
# def validate_auth_bypass():
