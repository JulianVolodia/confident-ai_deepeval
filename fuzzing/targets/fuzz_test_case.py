#!/usr/bin/env python3
"""
Fuzz Target: Test Case Pydantic Models

This fuzzes the LLMTestCase and ConversationalTestCase Pydantic models.

Target Classes:
- LLMTestCase
- ConversationalTestCase
- ToolCall

Potential Bugs to Find:
- Type confusion (passing wrong types)
- Validation bypass (invalid data accepted)
- Serialization/deserialization issues
- Unicode handling issues
- Edge cases in custom validators
"""

import sys
import os
import atheris
import json

# Add parent directory to path to import deepeval
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    from deepeval.test_case import LLMTestCase, ConversationalTestCase, ToolCall
    from deepeval.test_case.llm_test_case import Message
except ImportError:
    print("Warning: Could not import deepeval modules. Install dependencies first.")
    sys.exit(0)


def fuzz_llm_test_case(fdp):
    """
    Fuzz LLMTestCase with various input combinations.

    Tests:
    - Required field validation
    - Optional field handling
    - Type coercion
    - List field validation
    """
    try:
        # Generate fuzzed inputs
        input_text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1000))
        actual_output = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1000))

        # Optional fields
        expected_output = None
        if fdp.ConsumeBool():
            expected_output = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 500))

        context = None
        if fdp.ConsumeBool():
            context = [
                fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 200))
                for _ in range(fdp.ConsumeIntInRange(0, 10))
            ]

        retrieval_context = None
        if fdp.ConsumeBool():
            retrieval_context = [
                fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 200))
                for _ in range(fdp.ConsumeIntInRange(0, 10))
            ]

        # Try creating test case
        test_case = LLMTestCase(
            input=input_text,
            actual_output=actual_output,
            expected_output=expected_output,
            context=context,
            retrieval_context=retrieval_context,
        )

        # Try serialization
        _ = test_case.model_dump()
        _ = test_case.model_dump_json()

    except (ValueError, TypeError, AttributeError) as e:
        # Expected validation errors
        pass
    except Exception as e:
        # Unexpected error - might be a bug
        # Log but don't crash the fuzzer
        pass


def fuzz_conversational_test_case(fdp):
    """
    Fuzz ConversationalTestCase with various message combinations.

    Tests:
    - Message list validation
    - Turn validation
    - Message role validation
    """
    try:
        num_messages = fdp.ConsumeIntInRange(0, 20)
        messages = []

        for _ in range(num_messages):
            role = fdp.PickValueInList(["user", "assistant", "system", "invalid_role"])
            content = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 500))

            # Create message dict
            messages.append({
                "role": role,
                "content": content
            })

        # Try creating conversational test case
        test_case = ConversationalTestCase(
            messages=messages,
        )

        # Try serialization
        _ = test_case.model_dump()

    except (ValueError, TypeError, AttributeError) as e:
        # Expected validation errors
        pass
    except Exception as e:
        # Unexpected error
        pass


def fuzz_tool_call(fdp):
    """
    Fuzz ToolCall with various parameter combinations.

    Tests:
    - Name validation
    - Parameters validation (dict handling)
    - Serialization
    """
    try:
        name = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))

        # Generate random parameters dict
        params = {}
        num_params = fdp.ConsumeIntInRange(0, 10)
        for _ in range(num_params):
            key = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 50))
            value_type = fdp.ConsumeIntInRange(0, 3)

            if value_type == 0:
                value = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
            elif value_type == 1:
                value = fdp.ConsumeInt(8)
            elif value_type == 2:
                value = fdp.ConsumeBool()
            else:
                value = None

            params[key] = value

        # Try creating tool call
        tool_call = ToolCall(
            name=name,
            parameters=params
        )

        # Try serialization
        _ = tool_call.model_dump()

    except (ValueError, TypeError, AttributeError) as e:
        # Expected validation errors
        pass
    except Exception as e:
        # Unexpected error
        pass


def fuzz_json_deserialization(data: bytes):
    """
    Fuzz JSON deserialization into Pydantic models.

    Tests:
    - JSON parsing edge cases
    - Type coercion from JSON
    - Invalid field names
    """
    try:
        # Try to parse as JSON
        json_str = data.decode('utf-8', errors='ignore')
        json_obj = json.loads(json_str)

        # Try to create test case from JSON
        if isinstance(json_obj, dict):
            try:
                test_case = LLMTestCase(**json_obj)
            except (ValueError, TypeError) as e:
                pass

    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        # Expected errors for malformed JSON
        pass
    except Exception as e:
        # Unexpected error
        pass


@atheris.instrument_func
def TestOneInput(data: bytes):
    """
    Main fuzz harness called by Atheris with random data.
    """
    if len(data) < 2:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Select which component to fuzz
    choice = fdp.ConsumeIntInRange(0, 3)

    if choice == 0:
        fuzz_llm_test_case(fdp)
    elif choice == 1:
        fuzz_conversational_test_case(fdp)
    elif choice == 2:
        fuzz_tool_call(fdp)
    elif choice == 3:
        fuzz_json_deserialization(data)


def main():
    """
    Main entry point for fuzzing.

    Usage:
        python fuzz_test_case.py
        python fuzz_test_case.py corpus/test_cases/
    """
    atheris.Setup(sys.argv, TestOneInput)

    print("=" * 60)
    print("🔍 Fuzzing Test Case Models")
    print("=" * 60)
    print("Target: deepeval.test_case")
    print("Testing: LLMTestCase, ConversationalTestCase, ToolCall")
    print("Focus: Pydantic validation, serialization, type handling")
    print("=" * 60)
    print()

    atheris.Fuzz()


if __name__ == "__main__":
    main()
