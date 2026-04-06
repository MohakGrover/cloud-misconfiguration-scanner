import subprocess
import time
import webbrowser
import os
import signal
import sys

def main():
    print("Starting Cloud Scanner Dashboard...")
    
    # Start Backend
    print("Starting Flask Backend on port 5000...")
    backend = subprocess.Popen(
        [sys.executable, "-m", "cloud_scanner.dashboard.app"],
        cwd=os.getcwd()
    )
    
    # Start Frontend
    print("Starting React Frontend on port 3000...")
    frontend_dir = os.path.join(os.getcwd(), "cloud_scanner", "dashboard", "frontend")
    frontend = subprocess.Popen(
        ["npm", "run", "dev", "--", "--port", "3000"],
        cwd=frontend_dir,
        shell=True
    )
    
    print("Waiting for services to initialize...")
    time.sleep(5)
    
    print("Opening Dashboard in browser...")
    webbrowser.open("http://localhost:3000")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping services...")
        backend.terminate()
        # Frontend via npm relies on shell, harder to kill cleanly cross-platform without shell=False or tree kill
        # For dev script, letting user Ctrl+C is usually fine as shell propagates
        frontend.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
