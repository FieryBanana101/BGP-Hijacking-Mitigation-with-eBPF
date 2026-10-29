import json
import requests
import socket
import struct
import os
import time

OLLAMA_PORT = 11434
OLLAMA_API = f"http://localhost:{OLLAMA_PORT}/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:1.5b"
CONTAINER_NAME = "clab-bgp-lab-AS100"
INTERFACE = "eth1"

CC = "clang"
CFLAGS = "-O2 -I/usr/include/x86_64-linux-gnu"
TEMPLATE = "ebpf_template.c"
OUT = "ebpf"
C_OUT = f"{OUT}.c"
OBJ_OUT = f"{OUT}.o"


def ip_to_hex(ip_str):
    packed_ip = socket.inet_aton(ip_str)
    unpacked_ip = struct.unpack("!L", packed_ip)[0]
    return f"__builtin_bswap32(0x{unpacked_ip:08X})"


def prompt_qwen(alert_text):
    print("Sending system log to Ollama...")

    prompt = f"""
        Extract the malicious source IP address from this network alert.
        Alert: "{alert_text}"
        Respond ONLY with a JSON object in this exact format: {{"malicious_ip": "192.168.x.x"}}
    """
    
    response = requests.post(OLLAMA_API, json={
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False
    })
    
    result = response.json()["response"]
    return json.loads(result)["malicious_ip"]



def compile_and_attach(malicious_ip):
    print(f"Completing template for target IPv4 address: {malicious_ip}")
    
    # Adjust template by LLM response
    with open(TEMPLATE, "r") as f:
        template = f.read()
    
    c_hex_ip = ip_to_hex(malicious_ip)
    final_c_code = template.replace("__TARGET_IP__", c_hex_ip)
    
    with open(C_OUT, "w") as f:
        f.write(final_c_code)
        
    # Compile
    print(f"Compiling {TEMPLATE} into {C_OUT}")
    compile_cmd = f"{CC} {CFLAGS} -target bpf -c {C_OUT} -o {OBJ_OUT}"
    if os.system(compile_cmd) != 0:
        print("Compilation failed")
        exit(1)

    # Attach and run
    print(f"Attaching eBPF program to {INTERFACE}...")

    # Detach first, for easier testing
    detach_cmd = f"nsenter -t $(docker inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}) -n ip link set dev {INTERFACE} xdpgeneric off 2>/dev/null"
    os.system(detach_cmd) # No need to check the exit code because we expect this to fail if no attached process exist

    # Attach
    attach_cmd = f"nsenter -t $(docker inspect -f '{{{{.State.Pid}}}}' {CONTAINER_NAME}) -n ip link set dev {INTERFACE} xdpgeneric obj {OBJ_OUT} sec xdp"
    if os.system(attach_cmd) == 0:
        print(f"Mitigation active on {INTERFACE}. Traffic from {malicious_ip} is now blocked at the kernel level (success).")
    else:
        print("Failed to attach eBPF program.")



if __name__ == "__main__":
    with open('example.log', 'r') as f:
        simulated_log = f.read()
    
    print(f"System Log:\n{simulated_log}\n\n")
    start_time = time.time()
    
    extracted_ip = prompt_qwen(simulated_log)
    compile_and_attach(extracted_ip)
    
    print(f"Total mitigation time: {time.time() - start_time:.2f} seconds")