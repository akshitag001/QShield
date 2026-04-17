import os
import signal

# Kill the process on port 9003 (PID 49940)
pid = 49940
try:
    os.kill(pid, signal.SIGTERM)
    print(f"✅ Process {pid} terminated successfully")
except ProcessLookupError:
    print(f"⚠️ Process {pid} not found")
except PermissionError:
    print(f"❌ Permission denied to kill process {pid}")
