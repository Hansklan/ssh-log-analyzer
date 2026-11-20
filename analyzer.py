import json
import argparse

def parse_log(filename):
    failed_counts = {}
    successful_counts = {}
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
                if "Accepted password" in line:
                    parts = line.split()
                    ip = parts[parts.index("from") + 1]

                    if ip in successful_counts:
                        successful_counts[ip] += 1
                    else:
                        successful_counts[ip] = 1
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        raise SystemExit(1)

    return failed_counts, successful_counts


def detect_bruteforce(failed_counts, threshold=5):
    suspicious_ips = []

    for ip, count in failed_counts.items():
        if count >= threshold:
            suspicious_ips.append(ip)

    return suspicious_ips

def save_report(failed_counts, successful_counts, suspicious_ips):
    report = {
        "failed_login_attempts": failed_counts,
        "successful_login_attempts": successful_counts,
        "suspicious_ips": suspicious_ips
    }

    with open("report.json", "w") as file:
        json.dump(report, file, indent=4)


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
failed_counts, successful_counts = parse_log(args.file)
suspicious_ips = detect_bruteforce(
    failed_counts,
    args.threshold
)

print("Failed login attempts:", failed_counts)
print("Successful login attempts:", successful_counts)
print("Suspicious IP addresses:", suspicious_ips)

save_report(failed_counts, successful_counts, suspicious_ips)