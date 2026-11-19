#!/usr/bin/env python3
"""
Scalable BGP Hijacking Test Harness & Benchmarking Suite
Automates attack simulation, telemetry injection, LLM evaluation,
eBPF mitigation deployment, and end-to-end performance benchmarking.
Loads scenarios dynamically from external JSON files.
"""

import argparse
import dataclasses
import json
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional

# Import agent components from runner
import runner


@dataclasses.dataclass
class TestScenario:
    name: str
    description: str
    attack_type: str
    expected_attack_detected: bool
    expected_target_prefix: Optional[str]
    rogue_asn: Optional[int]
    simulated_telemetry: str
    live_route_command: Optional[str] = None
    live_withdraw_command: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "TestScenario":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            attack_type=d.get("attack_type", "none"),
            expected_attack_detected=d.get("expected_attack_detected", False),
            expected_target_prefix=d.get("expected_target_prefix"),
            rogue_asn=d.get("rogue_asn"),
            simulated_telemetry=d.get("simulated_telemetry", ""),
            live_route_command=d.get("live_route_command"),
            live_withdraw_command=d.get("live_withdraw_command")
        )


def load_scenarios_from_json(json_path: str) -> List[TestScenario]:
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Scenario configuration file '{json_path}' not found.")

    with open(json_path, "r") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list of scenario objects in '{json_path}'.")

    return [TestScenario.from_dict(item) for item in data]


class TestHarness:
    def __init__(self, target_container="clab-bgp-lab-AS300", interface="eth1", dry_run=False):
        self.target_container = target_container
        self.interface = interface
        self.dry_run = dry_run
        self.results = []

    def execute_in_container(self, command: str) -> bool:
        """Executes a command inside the target network container."""
        if self.dry_run:
            print(f"Executing inside {self.target_container}: {command}")
            return True

        full_cmd = ["docker", "exec", "-t", self.target_container, "sh", "-c", command]
        try:
            res = subprocess.run(full_cmd, capture_output=True, text=True, timeout=10)
            return res.returncode == 0
        except Exception as e:
            print(f"Error: Container execution error: {e}")
            return False

    def run_scenario(self, scenario: TestScenario, live_injection: bool = False) -> Dict:
        print("\n" + "=" * 75)
        print(f"RUNNING SCENARIO: {scenario.name}")
        print(f"Description: {scenario.description}")
        print("=" * 75)

        record = {
            "name": scenario.name,
            "attack_type": scenario.attack_type,
            "expected_detected": scenario.expected_attack_detected,
            "actual_detected": False,
            "target_cidr": None,
            "expected_target_prefix": scenario.expected_target_prefix,
            "llm_latency_s": 0.0,
            "ebpf_latency_s": 0.0,
            "classification_correct": False,
            "target_match": False,
            "mitigation_deployed": False
        }

        # Step 1: Live Injection
        if live_injection and scenario.live_route_command:
            print("Injecting live hijacking scenario")
            injected = self.execute_in_container(scenario.live_route_command)
            if not injected:
                print("      Error: Warning: Live injection failed. Container may not be running.")
            time.sleep(1)

        # Step 2: Feed telemetry to LLM agent
        print("Sending telemetry event to LLM triage engine")
        t0 = time.time()
        try:
            decision = runner.prompt_qwen_bgp_triage(scenario.simulated_telemetry)
            t_llm = time.time() - t0
            record["llm_latency_s"] = round(t_llm, 3)
            print(f"      LLM Triage completed in {t_llm:.2f}s:")
            print(f"      Decision: {json.dumps(decision, indent=10)}")
        except Exception as e:
            print(f"      Error: LLM query error: {e}")
            decision = {"attack_detected": False}

        record["actual_detected"] = decision.get("attack_detected", False)
        record["classification_correct"] = (record["actual_detected"] == record["expected_detected"])
        record["target_cidr"] = decision.get("target_cidr") or decision.get("unauthorized_announced_prefix")

        # Step 3: Mitigation Action
        if record["actual_detected"]:
            target_cidr = str(record["target_cidr"] or "")
            mode = decision.get("filter_mode", 1)

            # Check if extracted target matches expectations
            if scenario.expected_target_prefix and target_cidr:
                expected_clean = scenario.expected_target_prefix.strip()
                target_clean = target_cidr.strip()
                if (expected_clean == target_clean) or (expected_clean in target_clean) or (target_clean in expected_clean):
                    record["target_match"] = True

            print(f"Compiling and deploying eBPF filter for {target_cidr}")
            t_ebpf_start = time.time()
            if not self.dry_run:
                deployed = runner.compile_and_attach(target_cidr, mode)
            else:
                c_net, c_mask, _ = runner.parse_cidr_to_hex(target_cidr)
                deployed = True
                print(f"      Template compiled with Net={c_net}, Mask={c_mask}")

            t_ebpf = time.time() - t_ebpf_start
            record["ebpf_latency_s"] = round(t_ebpf, 3)
            record["mitigation_deployed"] = deployed
        else:
            print("No attack detected. Skipping eBPF compilation (nominal behavior).")

        # Step 4: Cleanup / Teardown
        print("Cleaning up testing scenario")
        if live_injection and scenario.live_withdraw_command:
            self.execute_in_container(scenario.live_withdraw_command)

        self.results.append(record)
        return record

    def print_benchmark_report(self):
        max_name_len = max([len(r["name"]) for r in self.results] + [len("Scenario"), 36])
        col_w = max_name_len + 2

        col_classified = 14
        col_target = 15
        col_llm = 12
        col_ebpf = 11

        total_width = col_w + col_classified + col_target + col_llm + col_ebpf + 12

        print("\n" + "=" * total_width)
        title = "BGP HIJACK MITIGATION REPORT"
        print(f"{title:^{total_width}}")
        print("=" * total_width)

        header = (
            f"{'Scenario':<{col_w}} | "
            f"{'Classified':<{col_classified}} | "
            f"{'Target Match':<{col_target}} | "
            f"{'LLM Time':<{col_llm}} | "
            f"{'eBPF Time':<{col_ebpf}}"
        )
        print(header)
        print("-" * total_width)

        total_scenarios = len(self.results)
        correct_classifications = 0
        correct_targets = 0

        for r in self.results:
            is_correct = "PASS" if r["classification_correct"] else "FAIL"
            target_ok = "PASS" if (r["target_match"] or not r["expected_detected"]) else "FAIL"

            if r["classification_correct"]:
                correct_classifications += 1
            if r["target_match"] or not r["expected_detected"]:
                correct_targets += 1

            llm_time_str = f"{r['llm_latency_s']:.2f}s"
            ebpf_time_str = f"{r['ebpf_latency_s']:.2f}s" if r['ebpf_latency_s'] > 0 else "N/A"

            row = (
                f"{r['name']:<{col_w}} | "
                f"{is_correct:<{col_classified}} | "
                f"{target_ok:<{col_target}} | "
                f"{llm_time_str:<{col_llm}} | "
                f"{ebpf_time_str:<{col_ebpf}}"
            )
            print(row)

        print("=" * total_width)
        class_acc = (correct_classifications / total_scenarios * 100) if total_scenarios else 0
        target_acc = (correct_targets / total_scenarios * 100) if total_scenarios else 0
        avg_llm_time = sum(r["llm_latency_s"] for r in self.results) / total_scenarios if total_scenarios else 0

        print(f"Total Scenarios Evaluated:     {total_scenarios}")
        print(f"Classification Accuracy:       {class_acc:.1f}%")
        print(f"Target Identification Accuracy: {target_acc:.1f}%")
        print(f"Average LLM Decision Time:     {avg_llm_time:.2f} seconds")
        print("=" * total_width + "\n")


def main():
    parser = argparse.ArgumentParser(description="Autonomous BGP Hijack Mitigation Test Harness")
    parser.add_argument("--scenarios-file", type=str, default="scenarios.json", help="Path to scenarios JSON file (default: scenarios.json)")
    parser.add_argument("--scenario", type=str, default="all", help="Specific scenario name or 'all'")
    parser.add_argument("--live", action="store_true", help="Perform live route injection via Containerlab vtysh")
    parser.add_argument("--dry-run", action="store_true", help="Run without requiring root privileges / docker access")
    args = parser.parse_args()

    try:
        loaded_scenarios = load_scenarios_from_json(args.scenarios_file)
    except Exception as e:
        print(f"Error loading scenario file: {e}")
        sys.exit(1)

    harness = TestHarness(dry_run=args.dry_run)

    scenarios_to_run = (
        loaded_scenarios if args.scenario == "all"
        else [s for s in loaded_scenarios if s.name == args.scenario]
    )

    if not scenarios_to_run:
        print(f"Unknown scenario: '{args.scenario}'. Available: {[s.name for s in loaded_scenarios]}")
        sys.exit(1)

    for scenario in scenarios_to_run:
        harness.run_scenario(scenario, live_injection=args.live)

    harness.print_benchmark_report()


if __name__ == "__main__":
    main()
