from services.alert_extractor import *
from services.alert_analyzer import *

print("Alert IDs:", extract_alerts_ids())
print("Alert Names:", extract_alerts_names())
print("Alert Severities:", extract_alerts_severity())
print("Alert Risk Scores:", extract_alerts_risk_score())
print("Alert Events:", extract_alerts_source_ip_and_timestamp())
print("Alert_count:" , extract_alerts_count())

print("number_of_each_severity_level:" , number_of_each_severity_level())
print("highest risk_score: " , find_highest_risk_score())
print(f"average risk_score",risk_score_average())
print(f"high and critical alert: " , get_high_and_critical_alerts())

