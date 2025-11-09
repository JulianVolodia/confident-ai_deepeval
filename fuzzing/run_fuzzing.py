#!/usr/bin/env python3
"""
Unified Fuzzing Runner for DeepEval

This script provides a simple interface to run all fuzzing campaigns.

Usage:
    # Run all fuzz targets for 1 hour
    python run_fuzzing.py --target all --duration 3600

    # Run specific target
    python run_fuzzing.py --target dataset --duration 1800

    # Run property tests
    python run_fuzzing.py --target property --engine hypothesis

    # Continuous fuzzing (run overnight)
    python run_fuzzing.py --target all --duration 28800 --verbose
"""

import argparse
import subprocess
import sys
import os
import time
from pathlib import Path
from datetime import datetime


class Colors:
    """Terminal colors for pretty output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class FuzzingRunner:
    """Manages fuzzing campaigns for DeepEval"""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.fuzzing_dir = Path(__file__).parent
        self.targets_dir = self.fuzzing_dir / "targets"
        self.corpus_dir = self.fuzzing_dir / "corpus"
        self.crashes_dir = self.fuzzing_dir / "crashes"

        # Ensure directories exist
        self.corpus_dir.mkdir(exist_ok=True)
        self.crashes_dir.mkdir(exist_ok=True)

        # Available fuzz targets
        self.targets = {
            "dataset": {
                "script": "fuzz_dataset_parser.py",
                "description": "CSV/JSON/JSONL dataset parsing",
                "corpus": "datasets",
            },
            "testcase": {
                "script": "fuzz_test_case.py",
                "description": "Pydantic model validation (LLMTestCase, etc.)",
                "corpus": "test_cases",
            },
            "property": {
                "script": "property_tests.py",
                "description": "Property-based tests with Hypothesis",
                "engine": "hypothesis",
            },
        }

    def print_banner(self):
        """Print welcome banner"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}🔍 DeepEval Fuzzing Campaign Runner{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.END}\n")

    def print_info(self, message):
        """Print info message"""
        print(f"{Colors.BLUE}ℹ {message}{Colors.END}")

    def print_success(self, message):
        """Print success message"""
        print(f"{Colors.GREEN}✓ {message}{Colors.END}")

    def print_warning(self, message):
        """Print warning message"""
        print(f"{Colors.WARNING}⚠ {message}{Colors.END}")

    def print_error(self, message):
        """Print error message"""
        print(f"{Colors.FAIL}✗ {message}{Colors.END}")

    def check_dependencies(self):
        """Check if required fuzzing tools are installed"""
        self.print_info("Checking dependencies...")

        missing = []

        try:
            import atheris
            self.print_success("Atheris is installed")
        except ImportError:
            missing.append("atheris")
            self.print_warning("Atheris not found")

        try:
            import hypothesis
            self.print_success("Hypothesis is installed")
        except ImportError:
            missing.append("hypothesis")
            self.print_warning("Hypothesis not found")

        try:
            import deepeval
            self.print_success("DeepEval is installed")
        except ImportError:
            missing.append("deepeval")
            self.print_error("DeepEval not found (required)")

        if missing:
            self.print_error(f"\nMissing dependencies: {', '.join(missing)}")
            self.print_info("Run the deployment script to install dependencies:")
            self.print_info("  macOS:   ./fuzzing/deploy_macos.sh")
            self.print_info("  Windows: .\\fuzzing\\deploy_windows.ps1")
            return False

        return True

    def run_atheris_target(self, target_name, duration=None):
        """Run an Atheris-based fuzz target"""
        target_info = self.targets[target_name]
        script_path = self.targets_dir / target_info["script"]

        if not script_path.exists():
            self.print_error(f"Target script not found: {script_path}")
            return False

        self.print_info(f"Starting fuzzing target: {target_name}")
        self.print_info(f"Description: {target_info['description']}")

        # Build command
        cmd = [sys.executable, str(script_path)]

        # Add corpus directory if it exists
        if "corpus" in target_info:
            corpus_path = self.corpus_dir / target_info["corpus"]
            if corpus_path.exists():
                cmd.append(str(corpus_path))
                self.print_info(f"Using corpus: {corpus_path}")

        self.print_info(f"Command: {' '.join(cmd)}")

        if duration:
            self.print_info(f"Duration: {duration} seconds ({duration // 60} minutes)")

        # Run fuzzer
        start_time = time.time()
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )

            # Monitor output
            for line in process.stdout:
                if self.verbose:
                    print(line, end='')

                # Check for crashes
                if "ERROR" in line or "CRASH" in line or "ASAN" in line:
                    self.print_error(f"Potential crash detected!")
                    self.save_crash_log(target_name, line)

                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    self.print_info("Duration reached, stopping fuzzer...")
                    process.terminate()
                    process.wait(timeout=5)
                    break

            elapsed = time.time() - start_time
            self.print_success(f"Fuzzing completed in {elapsed:.1f} seconds")
            return True

        except KeyboardInterrupt:
            self.print_warning("Fuzzing interrupted by user")
            process.terminate()
            return False
        except Exception as e:
            self.print_error(f"Error running fuzzer: {e}")
            return False

    def run_hypothesis_target(self, target_name):
        """Run Hypothesis property-based tests"""
        target_info = self.targets[target_name]
        script_path = self.targets_dir / target_info["script"]

        if not script_path.exists():
            self.print_error(f"Target script not found: {script_path}")
            return False

        self.print_info(f"Running property-based tests: {target_name}")
        self.print_info(f"Description: {target_info['description']}")

        # Run pytest with hypothesis
        cmd = [
            sys.executable, "-m", "pytest",
            str(script_path),
            "-v",
            "--hypothesis-show-statistics",
            "--tb=short",
        ]

        self.print_info(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, check=False)
            if result.returncode == 0:
                self.print_success("All property tests passed!")
                return True
            else:
                self.print_warning("Some property tests failed (this might indicate bugs)")
                return False
        except Exception as e:
            self.print_error(f"Error running property tests: {e}")
            return False

    def save_crash_log(self, target_name, log_data):
        """Save crash information to crashes directory"""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        crash_file = self.crashes_dir / f"crash_{target_name}_{timestamp}.txt"

        with open(crash_file, 'w') as f:
            f.write(f"Crash detected at: {timestamp}\n")
            f.write(f"Target: {target_name}\n")
            f.write(f"{'=' * 60}\n")
            f.write(log_data)

        self.print_warning(f"Crash log saved to: {crash_file}")

    def run_campaign(self, target, duration=None):
        """Run a fuzzing campaign"""
        if target == "all":
            self.print_info("Running all fuzz targets sequentially...")

            # Calculate duration per target
            per_target_duration = duration // len(self.targets) if duration else None

            results = {}
            for target_name in self.targets.keys():
                if target_name == "property":
                    results[target_name] = self.run_hypothesis_target(target_name)
                else:
                    results[target_name] = self.run_atheris_target(target_name, per_target_duration)

                print()  # Blank line between targets

            # Summary
            print(f"\n{Colors.BOLD}Fuzzing Campaign Summary:{Colors.END}")
            for target_name, success in results.items():
                status = f"{Colors.GREEN}✓ PASS{Colors.END}" if success else f"{Colors.FAIL}✗ FAIL{Colors.END}"
                print(f"  {target_name}: {status}")

            return all(results.values())

        elif target in self.targets:
            target_info = self.targets[target]

            if target_info.get("engine") == "hypothesis":
                return self.run_hypothesis_target(target)
            else:
                return self.run_atheris_target(target, duration)
        else:
            self.print_error(f"Unknown target: {target}")
            self.print_info(f"Available targets: {', '.join(self.targets.keys())}, all")
            return False

    def list_targets(self):
        """List all available fuzz targets"""
        print(f"\n{Colors.BOLD}Available Fuzz Targets:{Colors.END}\n")

        for name, info in self.targets.items():
            engine = info.get("engine", "atheris")
            print(f"  {Colors.CYAN}{name:15}{Colors.END} - {info['description']}")
            print(f"    {'':15}   Engine: {engine}")

        print(f"\n  {Colors.CYAN}{'all':15}{Colors.END} - Run all targets sequentially\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Run fuzzing campaigns for DeepEval",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all targets for 1 hour
  python run_fuzzing.py --target all --duration 3600

  # Run dataset parser fuzzing for 30 minutes
  python run_fuzzing.py --target dataset --duration 1800

  # Run property tests
  python run_fuzzing.py --target property

  # List available targets
  python run_fuzzing.py --list
        """
    )

    parser.add_argument(
        "--target",
        choices=["dataset", "testcase", "property", "all"],
        help="Which target to fuzz"
    )
    parser.add_argument(
        "--duration",
        type=int,
        help="Duration in seconds (for Atheris targets)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available fuzz targets"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show verbose fuzzing output"
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="Skip dependency checks"
    )

    args = parser.parse_args()

    runner = FuzzingRunner(verbose=args.verbose)
    runner.print_banner()

    if args.list:
        runner.list_targets()
        return 0

    if not args.target:
        parser.print_help()
        print()
        runner.list_targets()
        return 1

    # Check dependencies
    if not args.no_check:
        if not runner.check_dependencies():
            return 1
        print()

    # Run fuzzing campaign
    success = runner.run_campaign(args.target, args.duration)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
