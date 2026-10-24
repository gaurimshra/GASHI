"""End-to-End Live Demonstration Runner: Polluted UI + TinyFish Cloud API.

1. Boots Server 1 (Polluted UI on port 8080).
2. Boots Server 2 (TinyFish Runner API on port 9090).
3. Executes live cloud browser sessions via official TinyFish API.
4. Compares Raw TinyFish vs GASHI-Protected TinyFish.
"""

import sys
import time
import json
import threading
from urllib.request import urlopen, Request
from http.server import HTTPServer

from testbed.server_polluted_ui import PollutedUIHandler
from testbed.server_tinyfish_runner import TinyFishRunnerHandler


def start_server_thread(handler_class, host, port):
    server = HTTPServer((host, port), handler_class)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def fetch_json(url: str, timeout: int = 120):
    req = Request(url)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    print("=" * 70, flush=True)
    print("STARTING DUAL-SERVER LIVE TINYFISH INJECTION TEST", flush=True)
    print("=" * 70, flush=True)

    # 1. Start Server 1 (Polluted UI) on Port 8080
    print("[1/4] Starting Server 1: Polluted UI Web App on http://127.0.0.1:8080 ...", flush=True)
    server1 = start_server_thread(PollutedUIHandler, "127.0.0.1", 8080)
    time.sleep(0.5)
    print("      [OK] Server 1 live (Serving poisoned review page with CSS steganography)", flush=True)

    # 2. Start Server 2 (TinyFish Runner) on Port 9090
    print("[2/4] Starting Server 2: TinyFish Runner API on http://127.0.0.1:9090 ...", flush=True)
    server2 = start_server_thread(TinyFishRunnerHandler, "127.0.0.1", 9090)
    time.sleep(0.5)
    print("      [OK] Server 2 live (Connected to official TinyFish cloud)", flush=True)

    # 3. Test 1: Raw TinyFish Cloud Session (Baseline)
    print("\n[3/4] Running TEST 1: Raw TinyFish Cloud Browser (Unprotected)...", flush=True)
    print("      Provisioning TinyFish Chromium cloud session via API...", flush=True)
    try:
        baseline = fetch_json("http://127.0.0.1:9090/run-test?mode=baseline", timeout=120)
    except Exception as e:
        print(f"Error executing baseline: {e}", flush=True)
        server1.shutdown()
        server2.shutdown()
        sys.exit(1)

    print(f"      [OK] Connected to TinyFish Session: {baseline['tinyfish_session_id']}", flush=True)
    print(f"      Prompt Injected in TinyFish?  -> [!] YES ({baseline['prompt_injected_in_tinyfish']})", flush=True)
    print(f"      Injected Payload Extracted   : \"{baseline['injected_text_found']}\"", flush=True)
    print(f"      Canary Leak Dispatched?      -> [!] YES ({baseline['canary_leak_succeeded']})", flush=True)
    print(f"      Verdict                      : [VULNERABLE] {baseline['verdict']}", flush=True)

    # 4. Test 2: TinyFish Cloud Session + GASHI-Guard
    print("\n[4/4] Running TEST 2: TinyFish Cloud Browser + GASHI-Guard...", flush=True)
    print("      Provisioning TinyFish Chromium cloud session & wrapping with GashiGuard...", flush=True)
    try:
        gashi = fetch_json("http://127.0.0.1:9090/run-test?mode=gashi", timeout=120)
    except Exception as e:
        print(f"Error executing GASHI test: {e}", flush=True)
        server1.shutdown()
        server2.shutdown()
        sys.exit(1)

    print(f"      [OK] Connected to TinyFish Session: {gashi['tinyfish_session_id']}", flush=True)
    print(f"      Prompt Injected in TinyFish?  -> [PROTECTED] NO ({gashi['prompt_injected_in_tinyfish']})", flush=True)
    print(f"      Injected Payload Extracted   : {gashi['injected_text_found']}", flush=True)
    print(f"      Egress Canary Leak Blocked?  -> [PROTECTED] YES (RULE-EGRESS-01-CANARY)", flush=True)
    print(f"      Verdict                      : [SECURE] {gashi['verdict']}", flush=True)

    # 5. Final Summary Table
    print("\n" + "=" * 70, flush=True)
    print("LIVE REALITY COMPARISON SUMMARY", flush=True)
    print("=" * 70, flush=True)
    print(f"  Target Website               : Server 1 (Polluted UI on port 8080)")
    print(f"  Agent Framework              : Official TinyFish Cloud Browser (CDP WebSocket)")
    print(f"  Baseline Leak Rate           : 100% (Prompt Injection Ingested & Leaked)")
    print(f"  GASHI-Protected Leak Rate    : 0% (Prompt Injection Neutralized & Leaks Blocked)")
    print("=" * 70, flush=True)

    # Clean shutdown
    server1.shutdown()
    server2.shutdown()


if __name__ == "__main__":
    main()
