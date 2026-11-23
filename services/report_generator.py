from services.alert_reporter import *
from services.alert_analyzer import *
from services.alert_search import *

def report_generator():
    report = {
        "total_alerts": extract_alerts_count(),
        "severity_counts": number_of_each_severity_level(),
        "average_risk_score": risk_score_average(),
        "highest_risk_alert": find_highest_risk_score(),
        "high_critical_alerts": get_high_and_critical_alerts(),
        "processed_alerts": generate_alert_report()
    }

    return report