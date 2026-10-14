
from collections import Counter

def analyze_logs(filename):
    failed_ips = Counter()
    successful_logins = 0
    failed_logins = 0

    try:
        with open(filename, "r") as file:
            for line in file:
                line = line.strip()

                if "FAILED" in line.upper():
                    failed_logins += 1

                    # Example format: FAILED login from 192.168.1.10
                    parts = line.split()
                    if parts:
                        ip = parts[-1]
                        failed_ips[ip] += 1

                elif "SUCCESS" in line.upper():
                    successful_logins += 1

        print("\n========== LOG ANALYSIS ==========")
        print(f"Successful logins: {successful_logins}")
        print(f"Failed logins:     {failed_logins}")

        print("\nFailed attempts by source:")
        if failed_ips:
            for ip, count in failed_ips.most_common():
                print(f"{ip}: {count} failed attempt(s)")

                if count >= 5:
                    print("  WARNING: Repeated failed attempts detected!")
        else:
            print("No failed login attempts found.")

    except FileNotFoundError:
        print("Error: Log file not found.")
    except OSError as error:
        print(f"Could not read the file: {error}")


print("CYBERSECURITY LOG ANALYZER")
filename = input("Enter the log filename: ").strip()
analyze_logs(filename)
