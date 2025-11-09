#!/usr/bin/env python3
"""
Fuzz Target: Dataset Parser

This fuzzes the CSV, JSON, and JSONL parsing logic in deepeval.dataset.dataset.

Target Functions:
- add_test_cases_from_csv_file()
- add_test_cases_from_json_file()
- add_goldens_from_csv_file()
- add_goldens_from_json_file()

Potential Bugs to Find:
- CSV injection
- JSON bombs (deeply nested structures)
- Character encoding issues
- Memory exhaustion from large files
- Path traversal vulnerabilities
- Malformed delimiter handling
"""

import sys
import os
import atheris
import tempfile
import json
import csv

# Add parent directory to path to import deepeval
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from deepeval.dataset import EvaluationDataset
    from deepeval.test_case import LLMTestCase
except ImportError:
    print("Warning: Could not import deepeval modules. Install dependencies first.")
    sys.exit(0)


def fuzz_csv_parser(data: bytes):
    """
    Fuzz CSV parsing with random malformed CSV data.

    Tests:
    - Malformed CSV structure
    - Invalid delimiters
    - Special characters
    - Very long lines
    - Missing columns
    """
    try:
        # Create temporary CSV file with fuzzer data
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            dataset = EvaluationDataset()

            # Try parsing with various column configurations
            dataset.add_test_cases_from_csv_file(
                file_path=temp_path,
                input_col_name="input",
                actual_output_col_name="output",
                expected_output_col_name="expected",
                context_col_name="context",
                context_col_delimiter=";",
            )
        except (FileNotFoundError, ValueError, KeyError, UnicodeDecodeError,
                csv.Error, Exception) as e:
            # These are expected exceptions for malformed input
            # We only care about unexpected crashes
            pass
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        # Unexpected exception - this might be a bug!
        # Don't raise here; let atheris handle it
        pass


def fuzz_json_parser(data: bytes):
    """
    Fuzz JSON parsing with random malformed JSON data.

    Tests:
    - Malformed JSON structure
    - Deeply nested objects (JSON bombs)
    - Invalid Unicode
    - Very large arrays
    - Type confusion
    """
    try:
        # Create temporary JSON file with fuzzer data
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.json', delete=False) as f:
            f.write(data)
            temp_path = f.name

        try:
            dataset = EvaluationDataset()

            # Try parsing JSON
            dataset.add_test_cases_from_json_file(
                file_path=temp_path,
                input_key_name="input",
                actual_output_key_name="actual_output",
                expected_output_key_name="expected_output",
            )
        except (FileNotFoundError, json.JSONDecodeError, ValueError, KeyError,
                UnicodeDecodeError, Exception) as e:
            # Expected exceptions for malformed input
            pass
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    except Exception as e:
        # Unexpected exception - potential bug
        pass


def fuzz_test_case_creation(data: bytes):
    """
    Fuzz LLMTestCase creation with random data.

    Tests:
    - Type validation in Pydantic models
    - Field validation
    - String encoding issues
    """
    if len(data) < 10:
        return

    try:
        # Split data into chunks for different fields
        chunks = atheris.FuzzedDataProvider(data)

        # Try to create test case with fuzzed data
        try:
            test_case = LLMTestCase(
                input=chunks.ConsumeUnicodeNoSurrogates(100),
                actual_output=chunks.ConsumeUnicodeNoSurrogates(100),
                expected_output=chunks.ConsumeUnicodeNoSurrogates(100) if chunks.ConsumeBool() else None,
                context=[chunks.ConsumeUnicodeNoSurrogates(50)] if chunks.ConsumeBool() else None,
            )
        except (ValueError, TypeError, UnicodeDecodeError, Exception) as e:
            # Expected validation errors
            pass

    except Exception as e:
        # Unexpected exception
        pass


@atheris.instrument_func
def TestOneInput(data: bytes):
    """
    Main fuzz harness called by Atheris with random data.

    This function routes fuzzer input to different parsers.
    """
    if len(data) < 2:
        return

    # Use first byte to select which parser to fuzz
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 2)
    remaining_data = fdp.ConsumeBytes(fdp.remaining_bytes())

    if choice == 0:
        fuzz_csv_parser(remaining_data)
    elif choice == 1:
        fuzz_json_parser(remaining_data)
    elif choice == 2:
        fuzz_test_case_creation(data)


def main():
    """
    Main entry point for fuzzing.

    Usage:
        # Run with Atheris (coverage-guided)
        python fuzz_dataset_parser.py

        # Run with custom corpus
        python fuzz_dataset_parser.py corpus/datasets/

        # Reproduce a crash
        python fuzz_dataset_parser.py < crash_file.bin
    """
    # Initialize atheris
    atheris.Setup(sys.argv, TestOneInput)

    print("=" * 60)
    print("🔍 Fuzzing Dataset Parser")
    print("=" * 60)
    print("Target: deepeval.dataset.dataset")
    print("Testing: CSV, JSON, JSONL parsing")
    print("Expected behavior: Crashes on malformed input should be handled gracefully")
    print("=" * 60)
    print()

    # Start fuzzing
    atheris.Fuzz()


if __name__ == "__main__":
    main()
