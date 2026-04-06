
import sys
import traceback
import json

def main():
    try:
        from cloud_scanner.core.scanner import CloudScanner
        scanner = CloudScanner(region='us-east-1')
        print("Starting scan...")
        scan_result = scanner.scan()
        print(f"Scan complete. Duration: {scan_result.duration_seconds}")
        print(f"Findings: {len(scan_result.findings)}")
        
        with open('results_debug.json', 'w') as f:
            json.dump(scan_result.to_dict(), f, indent=2)
            
    except Exception:
        with open('error.txt', 'w') as f:
            f.write(traceback.format_exc())
            print("Error occurred, check error.txt")

if __name__ == '__main__':
    main()
