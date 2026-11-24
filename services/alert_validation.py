import re
from urllib.parse import unquote


# =====================================================
# Helper functions
# =====================================================

def clean_text(value):
    """Lowercase the value and URL-decode it (twice, for double encoding like %252e)."""
    if value is None:
        return ""
    text = str(value)
    for _ in range(2):
        text = unquote(text)
    return text.lower()


def to_number(value):
    """Convert a value to a number. Return None if it is not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        return float(str(value).strip())
    except (ValueError, TypeError):
        return None


def find_regex(patterns, text):
    """Return the matched text of the first regex that is found, else None."""
    for pattern in patterns:
        found = re.search(pattern, text)
        if found:
            return found.group(0)
    return None


def find_keyword(keywords, text):
    """Return the first keyword found in text, else None."""
    for keyword in keywords:
        if keyword in text:
            return keyword
    return None


def get_event_text(alert, fields=None):
    """Join the important event fields (decoded) into one text."""
    event = alert.get("event") or {}

    if fields is None:
        fields = [
            "url.path",
            "url.query",
            "http.request.body.content",
        ]

    parts = []
    for field in fields:
        parts.append(clean_text(event.get(field)))

    return " ".join(parts)


def build_reason(attack_name, confirmed, failed, needed):
    """Make a readable explanation from confirmed / failed signals."""
    total = len(confirmed) + len(failed)
    text = f"{attack_name}: {len(confirmed)} of {total} checks passed (need {needed})"
    if confirmed:
        text += " | passed: " + " ; ".join(confirmed)
    if failed:
        text += " | failed: " + " ; ".join(failed)
    return text


# =====================================================
# Generic checkers (used by many validators)
# Every checker returns (status, reason)
#   status = "MATCH" / "MISMATCH" / "INSUFFICIENT"
#   reason = explanation text (None when the alert is simply not of this attack type)
# =====================================================

def check_text_attack(alert, attack_name, logic_keywords, evidence_patterns, reason_keywords):
    """
    For attacks that have a text pattern (SQLi, XSS, LFI, ...).

    3 signals:
      1. matched_pattern looks like the attack
      2. reason talks about the attack
      3. the real request (event) really contains the attack pattern

    2 or more signals -> MATCH, otherwise MISMATCH
    """
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = clean_text(rule.get("logic"))
    raw_pattern = evidence.get("matched_pattern")
    matched_pattern = clean_text(raw_pattern)
    reason = clean_text(evidence.get("reason"))

    # 1. Is this alert of this attack type?
    if find_keyword(logic_keywords, logic) is None:
        return "INSUFFICIENT", None

    # 2. Required evidence
    if not matched_pattern or not reason:
        return "INSUFFICIENT", f"{attack_name}: matched_pattern or reason is missing in evidence"

    # 3. Check signals
    confirmed = []
    failed = []

    found = find_regex(evidence_patterns, matched_pattern)
    if found is not None:
        confirmed.append(f"matched_pattern ('{raw_pattern}') looks like this attack")
    else:
        failed.append(f"matched_pattern ('{raw_pattern}') does not look like this attack")

    found = find_keyword(reason_keywords, reason)
    if found is not None:
        confirmed.append(f"reason contains '{found}'")
    else:
        failed.append("reason does not describe this attack")

    found = find_regex(evidence_patterns, get_event_text(alert))
    if found is not None:
        confirmed.append(f"the request itself contains '{found.strip()}'")
    else:
        failed.append("the request itself has no attack pattern")

    if len(confirmed) >= 2:
        return "MATCH", build_reason(attack_name, confirmed, failed, 2)
    return "MISMATCH", build_reason(attack_name, confirmed, failed, 2)


def check_threshold_attack(alert, attack_name, logic_keywords, count_key):
    """
    For attacks based on a count (brute force).
    MATCH if count >= threshold.
    """
    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}
    event = alert.get("event") or {}

    logic = clean_text(rule.get("logic"))

    # 1. Is this alert of this attack type?
    if find_keyword(logic_keywords, logic) is None:
        return "INSUFFICIENT", None

    # 2. Get count (evidence first, then event)
    count = to_number(evidence.get(count_key))
    if count is None:
        count = to_number(event.get(count_key))

    # 3. Get threshold (evidence first, then from logic text: "at least 20 ...")
    threshold = to_number(evidence.get("threshold"))
    if threshold is None:
        found = re.search(r"at least (\d+)", logic)
        if found:
            threshold = int(found.group(1))

    if count is None or threshold is None:
        return "INSUFFICIENT", f"{attack_name}: {count_key} or threshold not found in evidence/event"

    if count >= threshold:
        return "MATCH", f"{attack_name}: {count_key} = {count:g} reached the rule threshold ({threshold:g})"
    return "MISMATCH", f"{attack_name}: {count_key} = {count:g} is below the rule threshold ({threshold:g})"


# =====================================================
# Patterns and keywords
# =====================================================

SQL_LOGIC = ["sql injection", "sqli", "sql "]

SQL_PATTERNS = [
    r"\b(or|and)\b\s+(\d+|'[^']*'|\"[^\"]*\")\s*=\s*(\d+|'[^']*'|\"[^\"]*\")",  # or 1=1 , or 'a'='a'
    r"\bunion\b\s+(all\s+)?select\b",
    r"\bselect\b.+\bfrom\b",
    r"\binsert\s+into\b",
    r"\bdrop\s+(table|database)\b",
    r"\bdelete\s+from\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
    r"\bwaitfor\s+delay\b",
    r"information_schema",
    r"'\s*(--|#)",
    r";\s*(drop|select|insert|delete)\b",
]

SQL_REASON = [
    "sql",
    "boolean expression",
    "database query",
    "tautology",
    "union",
]


XSS_LOGIC = ["xss", "cross-site scripting", "script tag", "javascript execution", "javascript scheme"]

XSS_PATTERNS = [
    r"<\s*/?\s*script",
    r"javascript\s*:",
    r"\bon(error|load|click|mouseover|mouseenter|focus)\s*=",
    r"<\s*(svg|iframe|img|body|object|embed)\b",
    r"document\s*\.\s*(cookie|location|write)",
    r"\balert\s*\(",
    r"\beval\s*\(",
]

XSS_REASON = [
    "script",
    "javascript",
    "cross-site",
    "xss",
    "html injection",
    "markup",
    "event handler",
    "browser execution",
]


PATH_LOGIC = ["path traversal", "directory traversal", "traversal"]

PATH_PATTERNS = [
    r"\.\.[/\\]",
    r"\.\.;/",
    r"/etc/passwd",
    r"win\.ini",
    r"boot\.ini",
]

PATH_REASON = [
    "traversal",
    "parent directory",
    "parent-directory",
    "directory escape",
]


LFI_LOGIC = ["local file inclusion", "file inclusion", "local file", "local filesystem", "filesystem path"]

LFI_PATTERNS = [
    r"/etc/(passwd|shadow|hosts|group)",
    r"/proc/self/",
    r"/var/log/",
    r"php://(filter|input)",
    r"file://",
    r"expect://",
    r"\.\.[/\\]",
    r"[a-z]:\\windows",
    r"win\.ini",
    r"boot\.ini",
]

LFI_REASON = [
    "local file",
    "sensitive file",
    "sensitive local",
    "file path",
    "filesystem",
    "file inclusion",
    "file disclosure",
]


SSRF_LOGIC = ["ssrf", "server-side request forgery", "loopback", "cloud metadata", "user-controlled url"]

SSRF_PATTERNS = [
    r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\blocalhost\b",
    r"\b0\.0\.0\.0\b",
    r"\[?::1\]?",
    r"\b169\.254\.\d{1,3}\.\d{1,3}\b",
    r"metadata\.google\.internal",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    r"(file|gopher|dict)://",
]

SSRF_REASON = [
    "loopback",
    "localhost",
    "internal",
    "private network",
    "metadata",
    "server-side request",
    "user-controlled url",
]


CMD_LOGIC = ["command injection", "os command", "shell command", "operating-system command", "operating system command"]

CMD_SEPARATOR = r"(;|&&|\|\||\||`|\$\(|\n)"
CMD_NAMES = (
    r"(id|whoami|uname|cat|ls|pwd|wget|curl|nc|ncat|netcat|bash|sh|cmd|"
    r"powershell|ping|sleep|echo|nslookup|chmod|rm|ifconfig|ipconfig)"
)

CMD_PATTERNS = [
    CMD_SEPARATOR + r"\s*" + CMD_NAMES + r"\b",   # "; id" , "&& whoami"
    r"/bin/(ba|da)?sh",
    r"\bcmd(\.exe)?\s*/c",
    r"\bpowershell\b",
    r"\$\([^)]+\)",
    r"`[^`]+`",
]

CMD_REASON = [
    "command",
    "shell",
    "separator",
    "operating system",
    "operating-system",
]


EXEC_LOGIC = ["executable upload", "suspicious file upload", "executable file", "upload policy", "file upload"]

EXEC_PATTERNS = [
    r"(^|\.)(php[2-7]?|phtml|phar|jsp|jspx|asp|aspx|exe|dll|sh|bat|cmd|ps1|elf|jar|msi|vbs|cgi)($|[\s.?&;\"'])",
    r"x-msdownload|x-executable|x-dosexec|x-sh\b",
]

EXEC_REASON = [
    "executable",
    "upload",
    "dangerous",
    "script",
    "malicious",
]


LOGIN_LOGIC = ["failed login", "login attempts", "failed authentication", "login brute force"]
DIR_LOGIC = ["distinct paths", "directory brute force", "directory enumeration", "path enumeration"]

AUTH_LOGIC = [
    "authentication bypass",
    "auth bypass",
    "authenticated session",
    "without authentication",
    "authorization context",
    "unauthenticated",
]

AUTH_PATTERNS = [
    r"unauthori[sz]ed",
    r"missing auth",
    r"forged token",
    r"invalid token",
    r"alg.{0,5}none",
    r"without credentials",
    r"no session",
    r"privilege escalation",
]

AUTH_REASON = [
    "anonymous",
    "unauthenticated",
    "without authentication",
    "without an authenticated",
    "bypass",
    "unauthorized",
    "forged",
    "invalid token",
    "missing authentication",
    "protected endpoint",
]


# =====================================================
# Validators  ->  each returns (status, reason)
# =====================================================

def validate_sql_injection(alert):
    return check_text_attack(alert, "SQL Injection", SQL_LOGIC, SQL_PATTERNS, SQL_REASON)


def validate_xss(alert):
    return check_text_attack(alert, "XSS", XSS_LOGIC, XSS_PATTERNS, XSS_REASON)


def validate_path_traversal(alert):
    return check_text_attack(alert, "Path Traversal", PATH_LOGIC, PATH_PATTERNS, PATH_REASON)


def validate_lfi(alert):
    return check_text_attack(alert, "LFI", LFI_LOGIC, LFI_PATTERNS, LFI_REASON)


def validate_ssrf(alert):
    return check_text_attack(alert, "SSRF", SSRF_LOGIC, SSRF_PATTERNS, SSRF_REASON)


def validate_command_injection(alert):
    return check_text_attack(alert, "Command Injection", CMD_LOGIC, CMD_PATTERNS, CMD_REASON)


def validate_login_brute_force(alert):
    # evidence has failed_attempts + threshold (no matched_pattern)
    return check_threshold_attack(alert, "Login Brute Force", LOGIN_LOGIC, "failed_attempts")


def validate_directory_brute_force(alert):
    # evidence has distinct_paths + threshold (no matched_pattern)
    return check_threshold_attack(alert, "Directory Brute Force", DIR_LOGIC, "distinct_paths")


def validate_executable_upload(alert):
    attack_name = "Executable Upload"

    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}

    logic = clean_text(rule.get("logic"))
    reason = clean_text(evidence.get("reason"))

    # 1. Is this alert of this attack type?
    if find_keyword(EXEC_LOGIC, logic) is None:
        return "INSUFFICIENT", None

    # 2. Required evidence: some file info + reason
    evidence_text = ""
    for key in ["file_extension", "file_name", "matched_pattern", "content_type"]:
        evidence_text += " " + clean_text(evidence.get(key))
    evidence_text = evidence_text.strip()

    if not evidence_text or not reason:
        return "INSUFFICIENT", f"{attack_name}: file info or reason is missing in evidence"

    # 3. Check signals
    confirmed = []
    failed = []

    found = find_regex(EXEC_PATTERNS, evidence_text)
    if found is not None:
        confirmed.append(f"evidence ('{evidence_text}') has an executable extension/type")
    else:
        failed.append(f"evidence ('{evidence_text}') has no executable extension/type")

    found = find_keyword(EXEC_REASON, reason)
    if found is not None:
        confirmed.append(f"reason contains '{found}'")
    else:
        failed.append("reason does not describe an executable upload")

    event_text = get_event_text(alert, ["file.name", "file.extension", "file.mime_type"]).strip()
    found = find_regex(EXEC_PATTERNS, event_text)
    if found is not None:
        confirmed.append(f"the uploaded file in event ('{event_text}') is executable")
    else:
        failed.append("the uploaded file in event is not executable")

    if len(confirmed) >= 2:
        return "MATCH", build_reason(attack_name, confirmed, failed, 2)
    return "MISMATCH", build_reason(attack_name, confirmed, failed, 2)


def validate_auth_bypass(alert):
    attack_name = "Auth Bypass"

    rule = alert.get("rule") or {}
    evidence = alert.get("evidence") or {}
    event = alert.get("event") or {}

    logic = clean_text(rule.get("logic"))
    matched_pattern = clean_text(evidence.get("matched_pattern"))
    reason = clean_text(evidence.get("reason"))

    # 1. Is this alert of this attack type?
    if find_keyword(AUTH_LOGIC, logic) is None:
        return "INSUFFICIENT", None

    # 2. Required evidence
    has_info = (
        "authenticated" in evidence
        or matched_pattern
        or evidence.get("endpoint")
    )
    if not reason or not has_info:
        return "INSUFFICIENT", f"{attack_name}: reason or authentication info (authenticated/endpoint) is missing in evidence"

    confirmed = []
    failed = []

    # signal 1: evidence says "not authenticated" (or a known bypass pattern)
    found = find_regex(AUTH_PATTERNS, matched_pattern)
    if evidence.get("authenticated") is False:
        confirmed.append("evidence says authenticated = False")
    elif found is not None:
        confirmed.append(f"matched_pattern contains '{found}'")
    else:
        failed.append("evidence does not show an unauthenticated request")

    # signal 2: event shows an anonymous user got a successful response
    status = to_number(event.get("http.response.status_code"))
    success = status is not None and 200 <= status < 300

    user_name = clean_text(event.get("user.name"))
    no_user = user_name in ("anonymous", "guest", "unknown", "none") or event.get("user.roles") == []

    if success and no_user:
        confirmed.append(f"in event, user '{user_name or 'no roles'}' got a successful response ({status:g})")
    else:
        failed.append("in event, no anonymous user with a successful response")

    # signal 3: reason talks about bypass / anonymous access
    found = find_keyword(AUTH_REASON, reason)
    if found is not None:
        confirmed.append(f"reason contains '{found}'")
    else:
        failed.append("reason does not describe an auth bypass")

    if len(confirmed) >= 2:
        return "MATCH", build_reason(attack_name, confirmed, failed, 2)
    return "MISMATCH", build_reason(attack_name, confirmed, failed, 2)