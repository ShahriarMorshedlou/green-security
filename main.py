from services.alert_extractor import *

result = extract_alerts_ids()

print(result)

result2 = extract_alerts_names()
print(result2)

result3 = extract_alerts_severity()
print(result3)

result4 = extract_alerts_risk_score()
print(result4)