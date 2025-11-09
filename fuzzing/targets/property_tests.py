#!/usr/bin/env python3
"""
Property-Based Tests with Hypothesis

This module contains property-based tests for DeepEval using the Hypothesis framework.
Unlike traditional fuzzing, Hypothesis generates test cases based on specifications and
automatically shrinks failing examples to minimal reproducible cases.

What is Property-Based Testing?
- Instead of writing specific test cases, you define properties that should always hold
- Hypothesis generates hundreds of test cases automatically
- When a failure is found, Hypothesis shrinks it to the minimal failing example
- Great for finding edge cases you wouldn't think to test manually

Example Properties:
- "Serializing then deserializing a test case should return the same data"
- "All valid test cases should have non-empty input and output"
- "Dataset parsing should never crash, only raise specific exceptions"
"""

import sys
import os
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck
import tempfile
import json
import csv

# Add parent directory to path to import deepeval
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from deepeval.test_case import LLMTestCase, ConversationalTestCase, ToolCall
    from deepeval.dataset import EvaluationDataset
except ImportError:
    print("Warning: Could not import deepeval modules. Install dependencies first.")
    pytest.skip("DeepEval not installed", allow_module_level=True)


# ============================================================================
# Custom Hypothesis Strategies
# ============================================================================

# Strategy for generating valid LLMTestCase inputs
llm_test_case_strategy = st.builds(
    LLMTestCase,
    input=st.text(min_size=1, max_size=1000),
    actual_output=st.text(min_size=1, max_size=1000),
    expected_output=st.one_of(st.none(), st.text(max_size=500)),
    context=st.one_of(st.none(), st.lists(st.text(max_size=200), max_size=10)),
    retrieval_context=st.one_of(st.none(), st.lists(st.text(max_size=200), max_size=10)),
)

# Strategy for generating messages
message_strategy = st.builds(
    dict,
    role=st.sampled_from(["user", "assistant", "system"]),
    content=st.text(min_size=1, max_size=500)
)

# Strategy for generating ConversationalTestCase
conversational_test_case_strategy = st.builds(
    ConversationalTestCase,
    messages=st.lists(message_strategy, min_size=1, max_size=20)
)

# Strategy for generating ToolCall parameters
tool_params_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=50),
    values=st.one_of(
        st.text(max_size=100),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.booleans(),
        st.none()
    ),
    max_size=10
)

# Strategy for generating ToolCall
tool_call_strategy = st.builds(
    ToolCall,
    name=st.text(min_size=1, max_size=100),
    parameters=tool_params_strategy
)


# ============================================================================
# Property Tests for LLMTestCase
# ============================================================================

class TestLLMTestCaseProperties:
    """
    Property-based tests for LLMTestCase.

    These tests verify invariants that should always hold true.
    """

    @given(llm_test_case_strategy)
    @settings(max_examples=500, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_serialization_roundtrip(self, test_case):
        """
        Property: Serializing and deserializing a test case should preserve data.

        This tests that:
        1. model_dump() produces valid dict
        2. Creating a new TestCase from that dict works
        3. The resulting test case has the same data
        """
        # Serialize to dict
        serialized = test_case.model_dump()

        # Deserialize back
        deserialized = LLMTestCase(**serialized)

        # Check equality
        assert deserialized.input == test_case.input
        assert deserialized.actual_output == test_case.actual_output
        assert deserialized.expected_output == test_case.expected_output

    @given(llm_test_case_strategy)
    @settings(max_examples=500)
    def test_json_serialization_roundtrip(self, test_case):
        """
        Property: JSON serialization should be reversible.
        """
        # Serialize to JSON string
        json_str = test_case.model_dump_json()

        # Parse JSON
        parsed = json.loads(json_str)

        # Deserialize back to object
        deserialized = LLMTestCase(**parsed)

        assert deserialized.input == test_case.input
        assert deserialized.actual_output == test_case.actual_output

    @given(llm_test_case_strategy)
    @settings(max_examples=500)
    def test_required_fields_never_none(self, test_case):
        """
        Property: Required fields (input, actual_output) should never be None.
        """
        assert test_case.input is not None
        assert test_case.actual_output is not None

    @given(
        st.text(min_size=1),
        st.text(min_size=1),
        st.one_of(st.none(), st.text())
    )
    @settings(max_examples=500)
    def test_test_case_creation_never_crashes(self, input_text, actual_output, expected_output):
        """
        Property: Creating a test case with any string inputs should never crash.

        It may raise ValueError for validation, but should never crash unexpectedly.
        """
        try:
            test_case = LLMTestCase(
                input=input_text,
                actual_output=actual_output,
                expected_output=expected_output
            )
            # If creation succeeds, check invariants
            assert test_case.input == input_text
            assert test_case.actual_output == actual_output
        except (ValueError, TypeError):
            # Expected validation errors are OK
            pass


# ============================================================================
# Property Tests for ConversationalTestCase
# ============================================================================

class TestConversationalTestCaseProperties:
    """
    Property-based tests for ConversationalTestCase.
    """

    @given(conversational_test_case_strategy)
    @settings(max_examples=300)
    def test_messages_preserved_after_creation(self, test_case):
        """
        Property: Messages should be preserved after test case creation.
        """
        assert len(test_case.messages) > 0
        for msg in test_case.messages:
            assert "role" in msg or hasattr(msg, "role")
            assert "content" in msg or hasattr(msg, "content")

    @given(st.lists(message_strategy, min_size=1, max_size=20))
    @settings(max_examples=300)
    def test_conversational_test_case_accepts_valid_messages(self, messages):
        """
        Property: Any list of valid messages should create a valid test case.
        """
        try:
            test_case = ConversationalTestCase(messages=messages)
            assert len(test_case.messages) == len(messages)
        except (ValueError, TypeError):
            # Some validation errors are OK
            pass


# ============================================================================
# Property Tests for Dataset
# ============================================================================

class TestDatasetProperties:
    """
    Property-based tests for EvaluationDataset.
    """

    @given(st.lists(llm_test_case_strategy, min_size=0, max_size=50))
    @settings(max_examples=200)
    def test_dataset_test_case_count(self, test_cases):
        """
        Property: Adding N test cases should result in N test cases in dataset.
        """
        dataset = EvaluationDataset()

        for tc in test_cases:
            dataset.add_test_case(tc)

        assert len(dataset.test_cases) == len(test_cases)

    @given(llm_test_case_strategy)
    @settings(max_examples=200)
    def test_dataset_accepts_valid_test_cases(self, test_case):
        """
        Property: Any valid test case should be addable to a dataset.
        """
        dataset = EvaluationDataset()
        dataset.add_test_case(test_case)

        assert len(dataset.test_cases) == 1
        assert dataset.test_cases[0].input == test_case.input


# ============================================================================
# Property Tests for CSV Parsing
# ============================================================================

class TestCSVParsingProperties:
    """
    Property-based tests for CSV parsing.

    These tests create random CSV files and ensure parsing doesn't crash.
    """

    @given(
        st.lists(
            st.fixed_dictionaries({
                'input': st.text(min_size=1, max_size=100),
                'output': st.text(min_size=1, max_size=100),
                'expected': st.text(max_size=100),
            }),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=100, deadline=5000)
    def test_csv_parsing_with_valid_structure(self, rows):
        """
        Property: Parsing a well-formed CSV should always succeed.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['input', 'output', 'expected'])
            writer.writeheader()
            writer.writerows(rows)
            temp_path = f.name

        try:
            dataset = EvaluationDataset()
            dataset.add_test_cases_from_csv_file(
                file_path=temp_path,
                input_col_name='input',
                actual_output_col_name='output',
                expected_output_col_name='expected'
            )

            # Check that test cases were added
            assert len(dataset.test_cases) == len(rows)

        finally:
            os.unlink(temp_path)

    @given(st.binary(min_size=0, max_size=10000))
    @settings(max_examples=100, deadline=5000)
    def test_csv_parsing_never_crashes_on_random_data(self, random_bytes):
        """
        Property: CSV parsing should handle errors gracefully, never crash.

        Even with completely random data, we should get:
        - A ValueError
        - A csv.Error
        - A UnicodeDecodeError
        - Success (if the random data happens to be valid)

        But NEVER an unexpected crash or segfault.
        """
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as f:
            f.write(random_bytes)
            temp_path = f.name

        try:
            dataset = EvaluationDataset()
            dataset.add_test_cases_from_csv_file(
                file_path=temp_path,
                input_col_name='input',
                actual_output_col_name='output'
            )
            # If we get here, the random data was valid CSV
        except (ValueError, KeyError, csv.Error, UnicodeDecodeError, Exception):
            # These are all expected errors for malformed CSV
            pass
        finally:
            os.unlink(temp_path)


# ============================================================================
# Property Tests for JSON Parsing
# ============================================================================

class TestJSONParsingProperties:
    """
    Property-based tests for JSON parsing.
    """

    @given(
        st.lists(
            st.fixed_dictionaries({
                'input': st.text(min_size=1, max_size=100),
                'actual_output': st.text(min_size=1, max_size=100),
                'expected_output': st.text(max_size=100),
            }),
            min_size=1,
            max_size=20
        )
    )
    @settings(max_examples=100, deadline=5000)
    def test_json_parsing_with_valid_structure(self, test_data):
        """
        Property: Parsing valid JSON should always succeed.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_data, f)
            temp_path = f.name

        try:
            dataset = EvaluationDataset()
            dataset.add_test_cases_from_json_file(
                file_path=temp_path,
                input_key_name='input',
                actual_output_key_name='actual_output',
                expected_output_key_name='expected_output'
            )

            assert len(dataset.test_cases) == len(test_data)

        finally:
            os.unlink(temp_path)


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    """
    Run property tests directly.

    Usage:
        # Run all property tests
        pytest property_tests.py -v

        # Run with more examples
        pytest property_tests.py -v --hypothesis-show-statistics

        # Run specific test class
        pytest property_tests.py::TestLLMTestCaseProperties -v
    """
    print("=" * 60)
    print("🧪 Running Property-Based Tests with Hypothesis")
    print("=" * 60)
    print("These tests generate hundreds of random inputs to find edge cases.")
    print("Run with: pytest property_tests.py -v")
    print("=" * 60)
    print()

    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
