import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10
def parse_log_file(file_path):
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split(' ')
            ip_address = parts[0]
            endpoint = parts[6]
            status_code = parts[8]
            ip_counts[ip_address] += 1
            if status_code == "200":
                endpoint_counts[endpoint] += 1
            if status_code == "401":
                failed_logins[ip_address] += 1

    return ip_counts, endpoint_counts, failed_logins

def most_accessed_endpoint(endpoint_counts):
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed

def suspicious_activity(failed_logins):
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_to_csv(ip_counts, endpoint_counts, failed_logins):
    with open('log_analysis_results.csv', mode='w', newline='') as file:
        writer = csv.writer(file)

        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_counts.items():
            writer.writerow([endpoint, count])
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

def display_results(ip_counts, endpoint_counts, failed_logins):
    print("Requests per IP Address:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count}")
    print("\nMost Accessed Endpoint:")
    endpoint, count = most_accessed_endpoint(endpoint_counts)
    print(f"{endpoint}: {count} accesses")
    print("\nSuspicious Activity (Failed Login Attempts > 10):")
    suspicious_ips = suspicious_activity(failed_logins)
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count} failed login attempts")
    else:
        print("No suspicious activity detected.")

def main():
    log_file_path = 'sample.log'
    ip_counts, endpoint_counts, failed_logins = parse_log_file(log_file_path) 
    display_results(ip_counts, endpoint_counts, failed_logins)
    save_to_csv(ip_counts, endpoint_counts, failed_logins)
    
    print("\nAnalysis saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()
