def read_logs():
    with open("sample.log") as f:
        log_lines = []
        for line in f:
            line = line.strip()
            log_lines.append(line)
        return log_lines
    
def extract_ips(log_lines):
    ips = []
    for line in log_lines:
        if "Failed login" in line:
            text = line.split("from", 1)
            ip = text[1].strip()
            ips.append(ip)
            #print(f"Extracted IP: '{ip}'")
    return ips

def count_ips(ips):
    ip_count = {}
    for ip in ips:
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1

    return ip_count

def detect_suspicious(ip_count):
    print("Suspicious IPs:")
    for ip in ip_count:
        if ip_count[ip] >= 3:
            print(f"{ip} ({ip_count[ip]} attempts)")    

def main():
    log_lines = read_logs()
    ips = extract_ips(log_lines)
    ip_count = count_ips(ips)
    detect_suspicious(ip_count)

main()