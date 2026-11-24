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


def validate_directory_brute_force(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify Directory Brute Force from rule.logic

    directory_brute_force_logic_keywords = [
        "directory brute force",
        "directory enumeration"
    ]

    if not all(keyword in logic for keyword in directory_brute_force_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check Directory Brute Force patterns in matched_pattern

    directory_brute_force_evidence_patterns = [
        "404",
        "403",
        "admin",
        "backup",
        "config",
        "uploads",
        "phpmyadmin",
        ".env",
        "robots.txt",
        "directory listing"
    ]

    if any(pattern in matched_pattern for pattern in directory_brute_force_evidence_patterns):
        return "MATCH"

    # 4. Check Directory Brute Force keywords in reason

    directory_brute_force_reason_keywords = [
        "directory enumeration",
        "directory brute force",
        "multiple directory requests",
        "multiple path requests",
        "repeated requests",
        "directory discovery",
        "file and directory discovery",
        "web content discovery"
    ]

    if any(keyword in reason for keyword in directory_brute_force_reason_keywords):
        return "MATCH"

    return "MISMATCH"


def validate_command_injection(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify Command Injection from rule.logic

    command_injection_logic_keywords = [
        "command injection",
        "os command"
    ]

    if not all(keyword in logic for keyword in command_injection_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check Command Injection patterns in matched_pattern

    command_injection_evidence_patterns = [
        ";",
        "&&",
        "||",
        "|",
        "`",
        "$(",
        "/bin/sh",
        "/bin/bash",
        "whoami",
        "id",
        "cat /etc/passwd"
    ]

    if any(pattern in matched_pattern for pattern in command_injection_evidence_patterns):
        return "MATCH"

    # 4. Check Command Injection keywords in reason

    command_injection_reason_keywords = [
        "command injection",
        "os command execution",
        "shell command execution",
        "arbitrary command execution",
        "command chaining",
        "shell metacharacter",
        "system command execution"
    ]

    if any(keyword in reason for keyword in command_injection_reason_keywords):
        return "MATCH"

    return "MISMATCH"

def validate_executable_upload(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify Executable Upload from rule.logic

    executable_upload_logic_keywords = [
        "executable upload",
        "suspicious file upload"
    ]

    if not all(keyword in logic for keyword in executable_upload_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check Executable Upload patterns in matched_pattern

    executable_upload_evidence_patterns = [
        ".exe",
        ".php",
        ".jsp",
        ".asp",
        ".aspx",
        ".sh",
        ".bat",
        ".cmd",
        ".dll",
        ".elf",
        "application/x-executable",
        "application/x-msdownload"
    ]

    if any(pattern in matched_pattern for pattern in executable_upload_evidence_patterns):
        return "MATCH"

    # 4. Check Executable Upload keywords in reason

    executable_upload_reason_keywords = [
        "executable file upload",
        "suspicious file upload",
        "uploaded executable",
        "malicious file upload",
        "server-side script upload",
        "dangerous file extension",
        "executable content"
    ]

    if any(keyword in reason for keyword in executable_upload_reason_keywords):
        return "MATCH"

    return "MISMATCH"

def validate_auth_bypass(alert):

    # extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()


    # 1. Identify Authentication Bypass from rule.logic

    auth_bypass_logic_keywords = [
        "authentication bypass",
        "auth bypass"
    ]

    if not all(keyword in logic for keyword in auth_bypass_logic_keywords):
        return "INSUFFICIENT"

    # 2. Check required evidence

    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check Authentication Bypass patterns in matched_pattern

    auth_bypass_evidence_patterns = [
        "unauthorized access",
        "authentication bypass",
        "missing authentication",
        "invalid token",
        "forged token",
        "jwt none",
        "privilege escalation",
        "access without credentials"
    ]

    if any(pattern in matched_pattern for pattern in auth_bypass_evidence_patterns):
        return "MATCH"

    # 4. Check Authentication Bypass keywords in reason

    auth_bypass_reason_keywords = [
        "authentication bypass",
        "authorization bypass",
        "access without authentication",
        "missing authentication check",
        "invalid authentication",
        "forged authentication token",
        "unauthorized access",
        "security control bypass"
    ]

    if any(keyword in reason for keyword in auth_bypass_reason_keywords):
        return "MATCH"

    return "MISMATCH"


def validate_lfi(alert):

    # Extract attributes
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = (rule.get("logic") or "").lower()

    matched_pattern = (evidence.get("matched_pattern") or "").lower()
    reason = (evidence.get("reason") or "").lower()

    # 1. Identify attack type
    if not all(keyword in logic for keyword in ["local file inclusion", "file inclusion"]):
        return "INSUFFICIENT"

    # 2. Check required evidence
    if not matched_pattern or not reason:
        return "INSUFFICIENT"

    # 3. Check matched patterns
    if any(pattern in matched_pattern for pattern in [
        "../",
        "..\\",
        "/etc/passwd",
        "/etc/shadow",
        "file://",
        "php://filter",
        "php://input"
    ]):
        return "MATCH"

    # 4. Check reason
    if any(keyword in reason for keyword in [
        "local file inclusion",
        "sensitive file",
        "file disclosure",
        "local file",
        "path traversal"
    ]):
        return "MATCH"

    return "MISMATCH"