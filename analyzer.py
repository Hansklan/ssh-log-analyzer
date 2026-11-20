import json
import argparse

def parse_log(filename):
    failed_counts = {}
    try:
        with open(filename, "r") as file:
            for line in file:
                if "Failed password" in line:
                    parts = line.split()
                    ip = parts[parts.index("from") + 1]

                    if ip in failed_counts:
                        failed_counts[ip] += 1
                    else:
                        failed_counts[ip] = 1

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        raise SystemExit(1)

    return failed_counts


def detect_bruteforce(failed_counts, threshold=5):
    suspicious_ips = []

    for ip, count in failed_counts.items():
        if count >= threshold:
            suspicious_ips.append(ip)

    return suspicious_ips

def save_report(failed_counts, suspicious_ips):
    report = {
        "failed_login_attempts": failed_counts,
        "suspicious_ips": suspicious_ips
    }
    with open("report.json", "w") as file:
        json.dump(report, file, indent = 4)


def get_arguments():
    parser = argparse.ArgumentParser(
        description="SSH Log Analyzer"

    )
    parser.add_argument(
        "--file",
        default="sample_auth.log",
        help="Path to SSH Log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed attempts"
    )

    return parser.parse_args()


args = get_arguments()

result = parse_log(args.file)
suspicious_ips = detect_bruteforce(
    result,
    args.threshold
)


print("Failed login attempts:", result)
print("Suspicious IP addresses:", suspicious_ips)

save_report(result, suspicious_ips)