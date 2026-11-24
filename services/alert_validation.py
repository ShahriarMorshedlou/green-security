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


def validate_xss(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify XSS from rule.logic

    xss_logic_keywords = [
        "xss",
        "cross-site scripting"
    ]

    if not all(keyword in logic for keyword in xss_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check XSS patterns in matched_pattern

    xss_evidence_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "alert(",
        "document.cookie",
        "<svg",
        "<iframe"
    ]

    if any(pattern in matched_pattern for pattern in xss_evidence_patterns):
        return "MATCH"

    # 4. Check XSS keywords in reason

    xss_reason_keywords = [
        "script injection",
        "cross-site scripting",
        "malicious javascript",
        "html injection",
        "javascript execution",
        "browser execution"
    ]

    if any(keyword in reason for keyword in xss_reason_keywords):
        return "MATCH"

    return "MISMATCH"


def validate_path_traversal(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify Path Traversal from rule.logic

    path_traversal_logic_keywords = [
        "path traversal",
        "directory traversal"
    ]

    if not all(keyword in logic for keyword in path_traversal_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check Path Traversal patterns in matched_pattern

    path_traversal_evidence_patterns = [
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e",
        "/etc/passwd",
        "windows/win.ini",
        "boot.ini"
    ]

    if any(pattern in matched_pattern for pattern in path_traversal_evidence_patterns):
        return "MATCH"

    # 4. Check Path Traversal keywords in reason

    path_traversal_reason_keywords = [
        "directory traversal",
        "path traversal",
        "parent directory",
        "sensitive file",
        "file system access",
        "directory escape"
    ]

    if any(keyword in reason for keyword in path_traversal_reason_keywords):
        return "MATCH"

    return "MISMATCH"# def validate_lfi():


def validate_ssrf(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify SSRF from rule.logic

    ssrf_logic_keywords = [
        "ssrf",
        "server-side request forgery"
    ]

    if not all(keyword in logic for keyword in ssrf_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check SSRF patterns in matched_pattern

    ssrf_evidence_patterns = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "metadata.google.internal",
        "file://",
        "gopher://",
        "http://127.",
        "http://localhost"
    ]

    if any(pattern in matched_pattern for pattern in ssrf_evidence_patterns):
        return "MATCH"

    # 4. Check SSRF keywords in reason

    ssrf_reason_keywords = [
        "server-side request",
        "internal service",
        "internal network",
        "cloud metadata",
        "metadata endpoint",
        "localhost access",
        "internal resource"
    ]

    if any(keyword in reason for keyword in ssrf_reason_keywords):
        return "MATCH"

    return "MISMATCH"

def validate_login_brute_force(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify Login Brute Force from rule.logic

    brute_force_logic_keywords = [
        "brute force",
        "login"
    ]

    if not all(keyword in logic for keyword in brute_force_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check Login Brute Force patterns in matched_pattern

    brute_force_evidence_patterns = [
        "failed login",
        "failed authentication",
        "multiple login attempts",
        "repeated login attempts",
        "invalid credentials",
        "too many login attempts",
        "authentication failure"
    ]

    if any(pattern in matched_pattern for pattern in brute_force_evidence_patterns):
        return "MATCH"

    # 4. Check Login Brute Force keywords in reason

    brute_force_reason_keywords = [
        "repeated login attempts",
        "multiple failed logins",
        "repeated authentication failures",
        "credential guessing",
        "password guessing",
        "brute force attack",
        "account login attempts"
    ]

    if any(keyword in reason for keyword in brute_force_reason_keywords):
        return "MATCH"

    return "MISMATCH"


# def validate_directory_brute_force():

# def validate_command_injection():

# def validate_executable_upload():

# def validate_auth_bypass():
