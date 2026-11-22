from services.alert_extractor import *

print("Alert IDs:", extract_alerts_ids())
print("Alert Names:", extract_alerts_names())
print("Alert Severities:", extract_alerts_severity())
print("Alert Risk Scores:", extract_alerts_risk_score())
print("Alert Events:", extract_alerts_source_ip_and_timestamp())
print("Alert_count:" , extract_alerts_count())