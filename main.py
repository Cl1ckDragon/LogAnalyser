import argparse

def read_logs(filename):
    """Read lines from a log file and return them as a list."""
    with open(filename) as f:
        log_lines = [line.strip() for line in f]
    return log_lines
    
def extract_ips(log_lines):
    """Extract IPs from failed login attempts."""
    ips = []
    for line in log_lines:
        if "Failed login" in line:
            parts = line.split("from", 1)
            ip = parts[1].strip()
            ips.append(ip)
    return ips

def count_ips(ips):
    """Count how many times an IP appears."""
    ip_count = {}
    for ip in ips:
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1
    return ip_count

def detect_suspicious(ip_count, threshold = 3):
    """Print IPs with failed login attempts above threshold"""
    found_suspicious = False
    print("Suspicious IPs:")
    for ip, count in ip_count.items():
        if count >= threshold:
            print(f"{ip} ({count} attempts)")
            found_suspicious = True
    if not found_suspicious:
        print("No suspicious activity detected!")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description = "Detect suspicious IPs from a log file.")
    parser.add_argument("logfile", help = "Path to the log file to analyse")
    parser.add_argument("-t", "--threshold", type = int, default = 3,
                        help = "Number of failed attempts to flag an IP as suspicious (default: 3)")
    return parser.parse_args()

def main():
    args = parse_args()
    log_lines = read_logs(args.logfile)
    ips = extract_ips(log_lines)
    ip_count = count_ips(ips)
    detect_suspicious(ip_count, threshold = args.threshold)

if __name__ == "__main__":
    main()