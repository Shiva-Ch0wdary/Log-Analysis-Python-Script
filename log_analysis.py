import re
import csv
from collections import Counter
from prettytable import PrettyTable

# Configuration
LOG_FILE_PATH = "sample.log"
CSV_OUTPUT_PATH = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 5

def parse_log_file(file_path):
    with open(file_path, "r") as file:
        log_lines = file.readlines()
    
    parsed_logs = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status>\d+) .*'
    )
    
    for line in log_lines:
        match = log_pattern.match(line)
        if match:
            parsed_logs.append(match.groupdict())
    
    return parsed_logs

def count_requests_by_ip(parsed_logs):
    ip_count = Counter(log['ip'] for log in parsed_logs)
    return ip_count.most_common()

def find_most_accessed_endpoint(parsed_logs):
    endpoint_count = Counter(log['endpoint'] for log in parsed_logs)
    most_visited = endpoint_count.most_common(1)
    return most_visited[0] if most_visited else None

def identify_suspicious_ips(parsed_logs, threshold=FAILED_LOGIN_THRESHOLD):
    failed_logins = Counter(
        log['ip'] for log in parsed_logs if log['status'] == '401' or 'Invalid credentials' in log.get('message', '')
    )
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

def export_results_to_csv(ip_traffic_data, top_endpoint, suspicious_ips, output_path):
    with open(output_path, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_traffic_data:
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint:", "Access Count"])
        if top_endpoint:
            writer.writerow(top_endpoint)
        
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def display_analysis_results(ip_traffic_data, top_endpoint, suspicious_ips):
    print("\n Requests Per IP ")
    table = PrettyTable(["IP Address", "Request Count"])
    for ip, count in ip_traffic_data:
        table.add_row([ip, count])
    print(table)
    
    print("\n Most Frequently Accessed Endpoint ")
    if top_endpoint:
        print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")
    else:
        print("No endpoints accessed.")
    
    print("\n Suspicious Activity Detected ")
    if suspicious_ips:
        suspicious_table = PrettyTable(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_ips.items():
            suspicious_table.add_row([ip, count])
        print(suspicious_table)
    else:
        print("No suspicious activity detected.")

def main():
    parsed_logs = parse_log_file(LOG_FILE_PATH)
    ip_traffic_data = count_requests_by_ip(parsed_logs)
    top_endpoint = find_most_accessed_endpoint(parsed_logs)
    suspicious_ips = identify_suspicious_ips(parsed_logs)

    display_analysis_results(ip_traffic_data, top_endpoint, suspicious_ips)
    export_results_to_csv(ip_traffic_data, top_endpoint, suspicious_ips, CSV_OUTPUT_PATH)

    print(f"\nResults saved to {CSV_OUTPUT_PATH}")

if __name__ == "__main__":
    main()
