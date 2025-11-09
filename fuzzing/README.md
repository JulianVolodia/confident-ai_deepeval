# 🔍 Fuzzing Integration for DeepEval

## What is Fuzzing?

**Fuzzing** (or fuzz testing) is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a program. The goal is to discover bugs, crashes, memory leaks, or security vulnerabilities.

### Key Concepts

1. **Mutation-based Fuzzing**: Starts with valid inputs and mutates them randomly
2. **Generation-based Fuzzing**: Generates inputs from scratch based on format specifications
3. **Coverage-guided Fuzzing**: Uses code coverage feedback to guide input generation (e.g., AFL, libFuzzer)
4. **Property-based Testing**: Tests properties that should hold for all inputs (e.g., Hypothesis)

### Why Fuzz DeepEval?

DeepEval processes various types of user input:
- CSV/JSON/JSONL datasets
- LLM test cases with arbitrary fields
- Metric configurations
- CLI arguments
- Synthetic data generation parameters

These are all excellent fuzzing targets that could reveal:
- **Parsing bugs**: Malformed JSON/CSV handling
- **Validation bypasses**: Invalid data accepted by Pydantic models
- **Type confusion**: Unexpected data types causing crashes
- **Resource exhaustion**: Large inputs causing memory/CPU issues
- **Security issues**: Injection attacks, path traversal, etc.

---

## 🛠️ Fuzzing Tools Integrated

### 1. **Atheris** (Google's Python Fuzzer)
- Coverage-guided fuzzing engine
- Based on libFuzzer
- Works on macOS, Linux, and Windows
- Best for: Binary data, parsing, low-level bugs

### 2. **Hypothesis** (Property-based Testing)
- Generates test cases based on specifications
- Integrates with pytest
- Shrinks failing examples automatically
- Best for: Business logic, API contracts, data validation

### 3. **Python-AFL** (American Fuzzy Lop)
- Industry-standard fuzzer adapted for Python
- Excellent crash detection
- Works on macOS and Linux
- Best for: Finding deep bugs over long runs

---

## 📁 Directory Structure

```
fuzzing/
├── README.md                          # This file
├── targets/                           # Fuzz target implementations
│   ├── fuzz_dataset_parser.py         # Dataset CSV/JSON parsing
│   ├── fuzz_test_case.py              # LLMTestCase validation
│   ├── fuzz_synthesizer.py            # Synthesizer input processing
│   ├── fuzz_metrics.py                # Metric configuration parsing
│   └── property_tests.py              # Hypothesis property-based tests
├── corpus/                            # Seed inputs for fuzzing
│   ├── datasets/                      # Sample CSV/JSON files
│   ├── test_cases/                    # Sample test case JSONs
│   └── metrics/                       # Sample metric configs
├── crashes/                           # Discovered crashes saved here
├── deploy_macos.sh                    # macOS setup script
├── deploy_windows.ps1                 # Windows setup script
└── run_fuzzing.py                     # Unified fuzzing runner

```

---

## 🚀 Quick Start

### macOS Deployment

```bash
# Make the script executable
chmod +x fuzzing/deploy_macos.sh

# Run the deployment script
./fuzzing/deploy_macos.sh

# Start fuzzing
cd fuzzing
python run_fuzzing.py --target all --duration 3600
```

### Windows Deployment

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Run the deployment script
.\fuzzing\deploy_windows.ps1

# Start fuzzing
cd fuzzing
python run_fuzzing.py --target all --duration 3600
```

---

## 🎯 Fuzz Targets Explained

### Target 1: Dataset Parser (`fuzz_dataset_parser.py`)

**What it tests**: CSV, JSON, and JSONL parsing in `deepeval/dataset/dataset.py`

**Why fuzz it**:
- Handles user-uploaded files
- Complex parsing logic
- Could crash on malformed data

**Example bugs it might find**:
- CSV injection attacks
- JSON bombs (deeply nested structures)
- Character encoding issues
- Memory exhaustion from large files

### Target 2: Test Case Validation (`fuzz_test_case.py`)

**What it tests**: Pydantic model validation in `LLMTestCase` and `ConversationalTestCase`

**Why fuzz it**:
- Validates user input
- Type coercion could have edge cases
- Custom validators might fail unexpectedly

**Example bugs it might find**:
- Type confusion (e.g., passing objects instead of strings)
- Validation bypass (invalid data accepted)
- Crashes on unexpected field combinations

### Target 3: Synthesizer (`fuzz_synthesizer.py`)

**What it tests**: Synthetic data generation parameters

**Why fuzz it**:
- Processes complex configuration
- Generates data based on templates
- Interacts with LLM APIs

**Example bugs it might find**:
- Prompt injection vulnerabilities
- Invalid parameter combinations
- Resource exhaustion from generation loops

### Target 4: Metrics (`fuzz_metrics.py`)

**What it tests**: Metric configuration and evaluation

**Why fuzz it**:
- User-defined evaluation criteria
- Complex scoring logic
- Mathematical operations that could overflow

**Example bugs it might find**:
- Division by zero
- NaN/Infinity handling
- Invalid threshold values

---

## 📊 Running Fuzzing Campaigns

### Run All Targets (Recommended for CI/CD)

```bash
python run_fuzzing.py --target all --duration 1800
```

### Run Specific Target

```bash
# Fuzz dataset parser for 1 hour
python run_fuzzing.py --target dataset --duration 3600

# Fuzz with Hypothesis property tests
python run_fuzzing.py --target property --engine hypothesis
```

### Continuous Fuzzing (Run Overnight)

```bash
# Run for 8 hours with verbose output
python run_fuzzing.py --target all --duration 28800 --verbose
```

---

## 🐛 Analyzing Crashes

When fuzzing finds a crash, it's saved in `crashes/` directory:

```bash
# View crash details
cat crashes/crash_dataset_2025-01-15_14-23-45.txt

# Reproduce the crash
python fuzzing/targets/fuzz_dataset_parser.py < crashes/crash_dataset_input.bin
```

### Crash Triage Steps

1. **Verify the crash**: Can you reproduce it?
2. **Minimize the input**: Use the built-in minimizer
3. **Classify severity**: Is it a DoS, memory corruption, or logic bug?
4. **Create a regression test**: Add to the test suite
5. **Fix and verify**: Ensure the fix prevents the crash

---

## 🔬 Understanding Fuzzing Output

### Coverage Metrics

```
#12345: cov: 1234 ft: 567 corp: 89 exec/s: 234
```

- **cov**: Total code coverage (edges covered)
- **ft**: Features (unique code paths)
- **corp**: Corpus size (interesting inputs saved)
- **exec/s**: Executions per second (speed)

### What Good Fuzzing Looks Like

✅ Coverage increases over time
✅ New features discovered regularly
✅ Corpus grows with interesting inputs
✅ High execution speed (>100 exec/s)
✅ No crashes (or crashes get fixed)

### What to Investigate

⚠️ Coverage plateaus quickly (might need better seeds)
⚠️ Very slow execution (<10 exec/s) (might need optimization)
⚠️ No new features after initial run (might be too simple)

---

## 🏆 Best Practices

### 1. Start with Good Seed Corpus

Place sample valid inputs in `corpus/` directories:
- Small but diverse examples
- Both valid and edge-case inputs
- Examples that exercise different code paths

### 2. Run Fuzzing Regularly

```bash
# Add to CI/CD pipeline
- name: Fuzz Testing
  run: |
    python fuzzing/run_fuzzing.py --target all --duration 300
```

### 3. Triage Crashes Promptly

- Not all crashes are bugs (some might be intentional errors)
- Focus on crashes in unexpected code paths
- Prioritize security-relevant crashes

### 4. Integrate with Testing

```python
# Add fuzzing-discovered cases to regression tests
def test_dataset_parser_fuzzing_case_1():
    """Regression test from fuzzing campaign 2025-01-15"""
    with pytest.raises(ValueError):
        parse_malformed_csv(fuzzing_input)
```

---

## 📚 Learning Resources

### Books
- "The Fuzzing Book" - https://www.fuzzingbook.org/
- "The Art of Software Security Assessment"

### Tools Documentation
- Atheris: https://github.com/google/atheris
- Hypothesis: https://hypothesis.readthedocs.io/
- AFL: https://github.com/google/AFL

### Tutorials
- Google's Fuzzing Tutorial: https://github.com/google/fuzzing
- OWASP Fuzzing Guide: https://owasp.org/www-community/Fuzzing

---

## 🤝 Contributing Fuzz Targets

To add a new fuzz target:

1. Create a new file in `targets/`: `fuzz_yourfeature.py`
2. Implement the fuzz harness:

```python
import atheris
import sys

def TestOneInput(data):
    """Fuzz harness - this gets called with random data"""
    try:
        # Call your code with fuzzer-provided data
        your_function(data)
    except ValueError:
        # Expected exceptions are OK
        pass
    except Exception as e:
        # Unexpected exceptions might be bugs!
        raise

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

3. Add seed inputs to `corpus/yourfeature/`
4. Update `run_fuzzing.py` to include your target
5. Document expected behavior in this README

---

## 🔒 Security Considerations

### Responsible Disclosure

If fuzzing discovers a security vulnerability:

1. **DO NOT** commit crash inputs to public repo
2. **DO** create a private security advisory on GitHub
3. **DO** notify maintainers via security@example.com
4. **WAIT** for a fix before public disclosure

### Fuzzing in Production

❌ **NEVER** run fuzzing against production systems
❌ **NEVER** use production API keys for fuzzing
✅ **DO** use isolated test environments
✅ **DO** use rate-limited test API keys

---

## 📈 Measuring Success

Track these metrics over time:

- **Code coverage**: Target >80% coverage of parsing code
- **Bugs found**: Aim for diminishing returns (fewer bugs over time)
- **Corpus quality**: Growing corpus indicates good diversity
- **Execution speed**: Optimize for >100 executions/second

---

## 🎓 Educational Goals

After working with this fuzzing setup, you should understand:

1. ✅ What fuzzing is and when to use it
2. ✅ How coverage-guided fuzzing works
3. ✅ How to write effective fuzz targets
4. ✅ How to triage and fix fuzzing-discovered bugs
5. ✅ How to integrate fuzzing into CI/CD
6. ✅ The difference between fuzzing and traditional testing

---

## 📞 Support

- Issues: https://github.com/confident-ai/deepeval/issues
- Discussions: https://github.com/confident-ai/deepeval/discussions
- Documentation: https://docs.confident-ai.com/

Happy Fuzzing! 🚀
