from services.alert_analyzer import *
from services.alert_search import *
from pprint import pprint
from services.alert_reporter import *
from services.report_generator import report_generator
from output.json_writer import save_report
from services.optional_features import detect_duplicate_alert
from services.optional_features import sort_alerts_by_risk_score
from services.optional_features import search_by_destination_ip


def show_menu():
    print("\n========== Security Alert Analyzer ==========")
    print("\n1. Display alert statistics")
    print("\n2. Search alerts")
    print("\n3. Generate report")
    print("\n4. Detect duplicate alerts")
    print("\n5. Sort alerts by risk score")
    print("\n6. Search by destination IP")
    print("\n7. Exit")
    print("\n=============================================")


def main():
    while True:
        show_menu()
        choice = input("Enter your choice: ")
        if choice == "1":
            print("Alert_count:", extract_alerts_count())
            print("number_of_each_severity_level:", number_of_each_severity_level())
            print("highest risk_score: ", find_highest_risk_score())
            print(f"average risk_score", risk_score_average())
            print(f"high and critical alert: ", get_high_and_critical_alerts())

        elif choice == "2":
             name = input("Enter the alert name: ")
             results = search_alerts_by_name_or_part_of_name(name)
             if results:
                 pprint(results, sort_dicts=False)
             else:
                 print("No results")

        elif choice == "3":
            report = report_generator()
            save_report(report)
            print("Report generated successfully!")

        elif choice == "4":
            print(f"detect duplicate alerts: {detect_duplicate_alert()}")

        elif choice == "5":
            print(f"sorted alerts by risk score:  {sort_alerts_by_risk_score()}")

        elif choice == "6":
             ip = input("Enter the destination IP address: ")
             results = search_by_destination_ip(ip)
             pprint(results, sort_dicts=False)

        elif choice == "7":
            print("Exiting...")
            break

        else:
            print("Invalid Input")

if __name__ == "__main__":
    main()




from services.optional_features import validate_alerts

if __name__ == "__main__":
    result = validate_alerts()

    total = sum(len(items) for items in result.values())
    print("Total:", total)

    for status in ["MATCH", "MISMATCH", "INSUFFICIENT"]:
        print(f"\n===== {status} ({len(result[status])}) =====")
        for item in result[status]:
            print("rule id   :", item["rule_id"])
            print("rule name :", item["rule_name"])
            print("attack    :", item["attack_type"])
            print("reason    :", item["reason"])
            print()

# print("Alert IDs:", extract_alerts_ids())
# print("Alert Names:", extract_alerts_names())
# print("Alert Severities:", extract_alerts_severity())
# print("Alert Risk Scores:", extract_alerts_risk_score())
# print("Alert Events:", extract_alerts_source_ip_and_timestamp())
# print("Alert_count:", extract_alerts_count())
#
# print("number_of_each_severity_level:", number_of_each_severity_level())
# print("highest risk_score: ", find_highest_risk_score())
# print(f"average risk_score", risk_score_average())
# print(f"high and critical alert: ", get_high_and_critical_alerts())
#
# ip = input("Enter the IP address: ")
# results = search_alerts_by_source_ip(ip)
# if results:
#     pprint(results, sort_dicts=False)
# else:
#     print("No results")
#
# name = input("Enter the alert name: ")
# results = search_alerts_by_name_or_part_of_name(name)
# if results:
#     pprint(results, sort_dicts=False)
# else:
#     print("No results")
#
# severity = input("Enter severity level: ")
# results = filter_alerts_by_severity(severity)
#
# if results:
#     pprint(results, sort_dicts=False)
# else:
#     print("No results")
#
# print("security alerts report: ")
# report = generate_alert_report()
# pprint(report, sort_dicts=False)
#
# report = report_generator()
# save_report(report)
# print("Report generated successfully!")
#
# print(detect_duplicate_alert())
# print(f"sorted alerts by risk score:  {sort_alerts_by_risk_score()}")
#
# ip = input("Enter the destination IP address: ")
# results = search_by_destination_ip(ip)
# pprint(results, sort_dicts=False)
