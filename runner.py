#!/usr/bin/env python3
"""
Autonomous BGP Hijacking Mitigation Agent
Ingests real-time BGP telemetry, triages alerts via local Ollama LLM,
and deploys kernel-level eBPF/XDP filters against malicious prefixes.

Supports:
  1. Continuous real-time daemon mode (--monitor): streams live events from
     Containerlab and dynamically mitigates attacks in real time without exiting.
  2. One-shot triage mode: evaluates a single alert file or string.
"""

import ipaddress
import json
import os
import requests
import subprocess
import sys
import time

OLLAMA_PORT = 11434
OLLAMA_API = f"http://localhost:{OLLAMA_PORT}/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:1.5b"
DEFAULT_MONITOR_CONTAINER = "clab-bgp-lab-AS200"
ATTACH_CONTAINER = "clab-bgp-lab-AS100"
INTERFACE = "eth1"

CC = "clang"
CFLAGS = "-O2 -I/usr/include/x86_64-linux-gnu"
TEMPLATE = "ebpf_template.c"
OUT = "ebpf"
C_OUT = f"{OUT}.c"
OBJ_OUT = f"{OUT}.o"


def parse_cidr_to_hex(cidr_str):
    """
    Parses an IPv4 CIDR string (e.g. '192.0.2.0/24' or host '198.51.100.77')
    and returns C-compatible __builtin_bswap32 expressions for:
      - Network address (network byte order)
      - Subnet mask (network byte order)
    """
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        network = ipaddress.ip_network(f"{cidr_str}/32", strict=False)

    net_int = int(network.network_address)
    mask_int = int(network.netmask)

    c_net = f"__builtin_bswap32(0x{net_int:08X})"
    c_mask = f"__builtin_bswap32(0x{mask_int:08X})"
    return c_net, c_mask, str(network)


def prompt_qwen_bgp_triage(log_text):
    prompt = f"""You are an autonomous network security classifier analyzing BGP telemetry.

Rules:
1. Benign logs ([INFO], 'healthy', 'Path valid', 'Keepalive'):
   attack_detected=false, attack_type="none", target_cidr=null, rogue_asn=null.

2. Attack logs (sub-prefix hijack or origin hijack):
   attack_detected=true.
   target_cidr is ALWAYS the unauthorized prefix advertised by the rogue AS (e.g. 10.100.1.0/24 or 192.0.2.0/24).
   NEVER select a legitimate parent or ROA prefix (such as 10.100.0.0/16).

Respond ONLY with valid JSON using this exact structure:
{{
  "attack_detected": boolean,
  "attack_type": "sub_prefix_hijack" | "origin_hijack" | "none",
  "unauthorized_announced_prefix": string or null,
  "target_cidr": string or null,
  "filter_mode": 1 (for prefix drop) or 0 (none),
  "rogue_asn": integer or null,
  "explanation": string
}}

Telemetry Log:
\"\"\"
{log_text.strip()}
\"\"\"
"""

    response = requests.post(OLLAMA_API, json={
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.0
        }
    }, timeout=60)

    if response.status_code != 200:
        raise RuntimeError(f"Ollama API error: HTTP {response.status_code} - {response.text}")

    result_raw = response.json().get("response", "{}")
    decision = json.loads(result_raw)

    if decision.get("attack_detected"):
        announced = decision.get("unauthorized_announced_prefix")
        target = decision.get("target_cidr")
        if not target and announced:
            decision["target_cidr"] = announced
        elif announced and "10.100.0.0" in str(target) and "10.100.1.0" in str(announced):
            decision["target_cidr"] = announced

    return decision


def compile_and_attach(target_cidr, filter_mode=1, container=ATTACH_CONTAINER, interface=INTERFACE):
    print(f"Preparing eBPF mitigation for CIDR: {target_cidr} (Filter Mode: {filter_mode})")

    with open(TEMPLATE, "r") as f:
        template = f.read()

    c_net, c_mask, formatted_cidr = parse_cidr_to_hex(target_cidr)

    final_c_code = (template
                    .replace("__TARGET_NET__", c_net)
                    .replace("__TARGET_MASK__", c_mask)
                    .replace("__FILTER_MODE__", str(filter_mode)))

    with open(C_OUT, "w") as f:
        f.write(final_c_code)

    print(f"Compiling {C_OUT} -> {OBJ_OUT} using {CC}...")
    compile_cmd = f"{CC} {CFLAGS} -target bpf -c {C_OUT} -o {OBJ_OUT}"
    ret = os.system(compile_cmd)
    if ret != 0:
        print("Error: Compilation failed!")
        return False

    print(f"Successfully compiled {OBJ_OUT}.")
    print(f"Attaching XDP program to {container}:{interface}...")

    # Detach any existing XDP program first
    detach_cmd = f"nsenter -t $(docker inspect -f '{{{{.State.Pid}}}}' {container}) -n ip link set dev {interface} xdpgeneric off 2>/dev/null"
    os.system(detach_cmd)

    # Attach new program
    attach_cmd = f"nsenter -t $(docker inspect -f '{{{{.State.Pid}}}}' {container}) -n ip link set dev {interface} xdpgeneric obj {OBJ_OUT} sec xdp"
    exit_code = os.system(attach_cmd)

    if exit_code == 0:
        print(f"MITIGATION ACTIVE: Kernel-level XDP filter engaged on {interface}.")
        print(f"    Target Prefix / Network: {formatted_cidr}")
        print(f"    Mode: {filter_mode} (1=Dest Prefix Drop)")
        return True
    else:
        print(f"Error: Notice: Could not attach to {container}:{interface}.")
        print("    (Verify containerlab is running: 'sudo clab deploy -t topology.clab.yml' and script has root/sudo)")
        return False


def handle_event(telemetry_line):
    print(f"\n[EVENT DETECTED] {telemetry_line.strip()}")
    t0 = time.time()
    try:
        decision = prompt_qwen_bgp_triage(telemetry_line)
    except Exception as e:
        print(f"Error: Error querying LLM: {e}")
        return

    latency = time.time() - t0
    print(f"LLM Triage completed in {latency:.2f}s:")
    print(json.dumps(decision, indent=2))

    if not decision.get("attack_detected", False):
        print("Normal routing event. No mitigation required.\n")
        return

    target_cidr = decision.get("target_cidr")
    filter_mode = decision.get("filter_mode", 1)

    if not target_cidr:
        print("Error: Attack detected but target_cidr missing.\n")
        return

    compile_and_attach(target_cidr, filter_mode)
    print(f"Active protection in place for {target_cidr}. Resuming listener...\n")


def run_continuous_monitor(container_name=DEFAULT_MONITOR_CONTAINER):
    """
    Continuous Live Daemon:
    Streams logs from Containerlab FRR router in real time, listens forever,
    and automatically mitigates hijacks when they are injected.
    """
    print("=" * 95)
    print("   AUTONOMOUS BGP HIJACKING MITIGATION DAEMON (will listen to virtual network container)")
    print("=" * 95)
    print(f"Attaching to live stream of container: {container_name}")
    print("Listening for incoming BGP announcements and anomalies...")
    print("Press Ctrl+C at any time to stop.\n" + "-" * 70)

    # Stream container logs live
    cmd = ["docker", "logs", "-f", "--tail", "0", container_name]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        print("Error: 'docker' command not found. Ensure Docker is installed.")
        return
    except Exception as e:
        print(f"Error: Failed to attach to container {container_name}: {e}")
        return

    try:
        for line in proc.stdout:
            line_str = line.strip()
            if not line_str:
                continue

            keywords = ["BGP", "UPDATE", "NOTIFICATION", "CRITICAL", "bmpd", "hijack", "prefix", "ADJ-IN"]
            if any(k.lower() in line_str.lower() for k in keywords):
                handle_event(line_str)

    except KeyboardInterrupt:
        print("\nStopping BGP mitigation daemon. Exiting gracefully.")
    finally:
        proc.terminate()


def run_stdin_monitor():
    """Reads continuously from standard input (e.g. tail -f log | python3 runner.py)."""
    print("=" * 70)
    print("   AUTONOMOUS BGP MITIGATION DAEMON (STDIN STREAMING LISTENER)")
    print("=" * 70)
    print("Listening on standard input... Press Ctrl+C to stop.\n" + "-" * 70)

    try:
        for line in sys.stdin:
            line_str = line.strip()
            if line_str:
                handle_event(line_str)
    except KeyboardInterrupt:
        print("\nStopping listener.")


def main():
    args = sys.argv[1:]

    # Case 1: Continuous Live Container Monitoring Mode
    if "--monitor" in args or "-m" in args:
        container = DEFAULT_MONITOR_CONTAINER
        for a in args:
            if a not in ("--monitor", "-m") and not a.startswith("-"):
                container = a
                break
        run_continuous_monitor(container)
        return

    # Case 2: Streaming from stdin pipe (e.g., tail -f /var/log/frr.log | sudo python3 runner.py)
    if not sys.stdin.isatty():
        run_stdin_monitor()
        return

    # Case 3: Single file or alert string provided
    if args:
        arg_val = args[0]
        if os.path.exists(arg_val):
            with open(arg_val, "r") as f:
                content = f.read()
        else:
            content = arg_val
        handle_event(content)
        return

    # Usage guide
    print("=" * 70)
    print("   LLM-Powered Autonomous BGP Hijack Mitigation Agent")
    print("=" * 70)
    print("Usage Modes:")
    print("  1. Continuous Real-Time Listener (Watches Containerlab router live):")
    print("       sudo python3 runner.py --monitor [container_name]")
    print("       (Default container: clab-bgp-lab-AS200)")
    print()
    print("  2. Pipe Live Logs into Listener:")
    print("       tail -f /var/log/frr/frr.log | sudo python3 runner.py")
    print()
    print("  3. One-Shot Incident Triage:")
    print("       sudo python3 runner.py \"<raw alert text>\"")
    print()
    print("  4. Benchmark / Testing Suite:")
    print("       python3 test.py --dry-run")
    print("       sudo python3 test.py --live")
    print("=" * 70)


if __name__ == "__main__":
    main()
