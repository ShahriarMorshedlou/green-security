from services import alert_extractor

print("Alert IDs:", alert_extractor.extract_alerts_ids())

print("Alert Names:", alert_extractor.extract_alerts_names())

print("Alert Severities:", alert_extractor.extract_alerts_severity())

print("Alert Risk Scores:", alert_extractor.extract_alerts_risk_score())

print("Alert Source IPs and Timestamps:",
      alert_extractor.extract_alerts_source_ip_and_timestamp())
