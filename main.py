from services.alert_analyzer import *
from services.alert_search import *
from pprint import pprint
from services.alert_reporter import *
from services.report_generator import report_generator
from output.json_writer import save_report
from services.optional_features import detect_duplicate_alert
print(detect_duplicate_alert())
print("Alert IDs:", extract_alerts_ids())
print("Alert Names:", extract_alerts_names())
print("Alert Severities:", extract_alerts_severity())
print("Alert Risk Scores:", extract_alerts_risk_score())
print("Alert Events:", extract_alerts_source_ip_and_timestamp())
print("Alert_count:", extract_alerts_count())

print("number_of_each_severity_level:", number_of_each_severity_level())
print("highest risk_score: ", find_highest_risk_score())
print(f"average risk_score", risk_score_average())
print(f"high and critical alert: ", get_high_and_critical_alerts())

ip = input("Enter the IP address: ")
results = search_alerts_by_source_ip(ip)
if results:
    pprint(results, sort_dicts=False)
else:
    print("No results")

name = input("Enter the alert name: ")
results = search_alerts_by_name_or_part_of_name(name)
if results:
    pprint(results, sort_dicts=False)
else:
    print("No results")

severity = input("Enter severity level: ")
results = filter_alerts_by_severity(severity)

if results:
    pprint(results, sort_dicts=False)
else:
    print("No results")

print("security alerts report: ")
report = generate_alert_report()
pprint(report, sort_dicts=False)


report = report_generator()
save_report(report)
print("Report generated successfully!")


print(detect_duplicate_alert())


