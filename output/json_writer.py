import json

def save_report(report):
    with open("output/report.json", "w") as outfile:
        json.dump(report, outfile , ensure_ascii=False, indent=4)