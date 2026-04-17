#!/usr/bin/env python
"""Kill all Uvicorn servers on port 9003."""

import os
import signal
import subprocess

pids = [11280, 44196, 45160, 49940, 55016]

print(f"Killing {len(pids)} old server processes...")

for pid in pids:
    try:
        # Try to kill the process
        os.kill(pid, signal.SIGTERM)
        print(f"  Killed PID {pid}")
    except ProcessLookupError:
        print(f"  PID {pid} already dead")
    except Exception as e:
        print(f"  ERROR killing PID {pid}: {e}")

print("\nWaiting for processes to terminate...")
import time
time.sleep(2)

# Verify they're gone
result = subprocess.run(
    'netstat -ano | findstr ":9003"',
    shell=True,
    capture_output=True,
    text=True
)

listening_count = len([line for line in result.stdout.split('\n') if 'LISTENING' in line])
print(f"\nServers still listening: {listening_count}")
print("Ready to start fresh server!")
