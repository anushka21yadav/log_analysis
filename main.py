from collections import Counter
import csv

log_file = "sample.log"

# 1) Count Requests per IP Address:
def count_req_per_ip_address(log_file):
    with open(log_file, 'r') as file:
        lines = file.readlines()

    ip_add = [l.split()[0] for l in lines if l.strip()]

    ip_count = Counter(ip_add)

    sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

    print(f"{'IP Address':<20} {'Request Count':<10}")
    print("-" * 30)
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count:<10}")
    print()

    return sorted_ips

# 2) Identify the Most Frequently Accessed Endpoint
def find_most_asscessed_endpoint(log_file):
    with open(log_file, 'r') as file:
        lines = file.readlines()

    endpoints = [l.split()[6] for l in lines if l.strip() and len(l.split()) > 6]

    endpoint_counts = Counter(endpoints)
    
    sorted_endpoint = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
    most_accessed, count = sorted_endpoint[0][0], sorted_endpoint[0][1]
    
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed} (Accessed {count} times)")
    print()

    return most_accessed, count

# 3) Detect Suspicious Activities
def detect_suspicious_activity(log_file, threshold=10):
    with open(log_file, 'r') as file:
        lines = file.readlines()
    
    failed_ips = [l.split()[0] for l in lines if "401" in l or "Invalid credentials" in l]
    
    failed_counts = Counter(failed_ips)
    
    suspicious_ips = {ip: count for ip, count in failed_counts.items() if count > threshold}
    
    if suspicious_ips:
        print("Suspicious Activity Detected:")
        print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")
    
    return suspicious_ips

# Save Results to CSV
def save_results(ip_requests, most_accessed_endpoint, suspicious_activities, output_file="log_analysis_results.csv"):
    with open(output_file, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        # 1) Count Requests per IP Address:
        csvwriter.writerow(['Requests per IP Address'])
        csvwriter.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests:
            csvwriter.writerow([ip, count])
        
        # 2) Identify the Most Frequently Accessed Endpoint
        csvwriter.writerow([])
        csvwriter.writerow(['Most Accessed Endpoint'])
        csvwriter.writerow(['Endpoint', 'Access Count'])
        csvwriter.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # 3) Detect Suspicious Activities
        csvwriter.writerow([])
        csvwriter.writerow(['Suspicious Activity Detected'])
        csvwriter.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activities.items():
            csvwriter.writerow([ip, count])
    
    print(f"\nResults saved to '{output_file}'.")

ip_requests = count_req_per_ip_address(log_file)
most_accessed_endpoint = find_most_asscessed_endpoint(log_file)
suspicious_activities = detect_suspicious_activity(log_file)

save_results(ip_requests, most_accessed_endpoint, suspicious_activities)