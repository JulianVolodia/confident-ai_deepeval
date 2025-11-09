# 🚀 Fuzzing Quickstart Guide

Get started with fuzzing DeepEval in under 5 minutes!

---

## What You'll Learn

By following this guide, you'll:
- ✅ Set up a complete fuzzing environment
- ✅ Run your first fuzzing campaign
- ✅ Understand the output
- ✅ Find and fix bugs

---

## Prerequisites

- **Python 3.9+** installed
- **15 minutes** of time
- **Curiosity** about finding bugs!

---

## Step 1: Installation (2 minutes)

### On macOS

```bash
# Navigate to the fuzzing directory
cd fuzzing

# Make the script executable
chmod +x deploy_macos.sh

# Run the deployment script
./deploy_macos.sh
```

### On Windows

```powershell
# Open PowerShell as Administrator
# Navigate to the fuzzing directory
cd fuzzing

# Allow script execution (first time only)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# Run the deployment script
.\deploy_windows.ps1
```

### On Linux

```bash
# Same as macOS
cd fuzzing
chmod +x deploy_macos.sh  # Works on Linux too!
./deploy_macos.sh
```

**The script will:**
- ✓ Check your Python version
- ✓ Create a virtual environment
- ✓ Install fuzzing tools (Atheris, Hypothesis)
- ✓ Set up sample test data
- ✓ Verify everything works

---

## Step 2: Your First Fuzz Test (30 seconds)

Activate the virtual environment:

```bash
# macOS/Linux
source ../.venv-fuzzing/bin/activate

# Windows
..\.venv-fuzzing\Scripts\Activate.ps1
```

Run a quick property-based test:

```bash
python run_fuzzing.py --target property
```

**What's happening?**
- Hypothesis generates hundreds of random test cases
- Tests validate properties like "serialization should be reversible"
- If any property fails, you've found a bug!

**Expected output:**
```
═══════════════════════════════════════════════════════════
  🔍 DeepEval Fuzzing Campaign Runner
═══════════════════════════════════════════════════════════

ℹ Checking dependencies...
✓ Atheris is installed
✓ Hypothesis is installed
✓ DeepEval is installed

ℹ Running property-based tests: property
...

===== 25 passed in 3.42s =====
```

---

## Step 3: Run Coverage-Guided Fuzzing (5 minutes)

Now let's fuzz the dataset parser for 5 minutes:

```bash
python run_fuzzing.py --target dataset --duration 300 --verbose
```

**What's happening?**
- Atheris generates random CSV/JSON data
- Feeds it to the dataset parser
- Monitors code coverage to generate smarter inputs
- Looks for crashes, hangs, or unexpected behavior

**Expected output:**
```
═══════════════════════════════════════════════════════════
🔍 Fuzzing Dataset Parser
═══════════════════════════════════════════════════════════
Target: deepeval.dataset.dataset
Testing: CSV, JSON, JSONL parsing

#12345: cov: 1234 ft: 567 corp: 89 exec/s: 234
```

**Understanding the output:**
- `cov: 1234` - 1234 code edges covered
- `ft: 567` - 567 unique features found
- `corp: 89` - 89 interesting inputs saved
- `exec/s: 234` - 234 executions per second

---

## Step 4: Analyze Results (2 minutes)

### If No Crashes Found

Great! The code handles random input well. But let's verify:

```bash
# Check the crashes directory
ls crashes/

# Should be empty or have no recent files
```

### If Crashes Found

Exciting! You've found a bug:

```bash
# List crashes
ls crashes/

# View a crash
cat crashes/crash_dataset_2025-01-15_14-23-45.txt
```

**What to do:**
1. **Read the crash log** - What error occurred?
2. **Reproduce it** - Can you trigger it manually?
3. **Minimize the input** - What's the smallest input that crashes?
4. **Fix the bug** - Update the code to handle the case
5. **Add a regression test** - Ensure it doesn't happen again

---

## Step 5: Run a Full Campaign (Optional, 1 hour)

For comprehensive testing, run all targets:

```bash
# Run for 1 hour (great to run overnight or during lunch)
python run_fuzzing.py --target all --duration 3600 --verbose
```

This will fuzz:
- ✓ Dataset parsers (CSV, JSON, JSONL)
- ✓ Pydantic models (LLMTestCase, etc.)
- ✓ Property-based tests

**Pro tip:** Run this weekly or integrate into CI/CD!

---

## Common Questions

### Q: What if Atheris fails to install?

**A:** Atheris requires a C compiler.

- **macOS:** Install Xcode Command Line Tools
  ```bash
  xcode-select --install
  ```

- **Windows:** Install Visual Studio Build Tools
  - Download: https://visualstudio.microsoft.com/downloads/
  - Select "Desktop development with C++"

- **Linux:** Install clang
  ```bash
  sudo apt-get install clang libclang-dev
  ```

### Q: How long should I fuzz?

**A:** It depends on your goals:

- **Quick smoke test:** 5 minutes
- **Pull request validation:** 10-15 minutes
- **Nightly CI:** 30-60 minutes
- **Comprehensive audit:** 8+ hours (run overnight)

### Q: What's a "good" execution speed?

**A:**
- **< 10 exec/s:** Slow, might need optimization
- **10-100 exec/s:** Normal for complex parsing
- **100-1000 exec/s:** Good!
- **> 1000 exec/s:** Excellent!

### Q: Should I commit the corpus to git?

**A:** Generally, no. The corpus can get large. But you can:
- Commit a few small seed files
- Add `corpus/` to `.gitignore` for generated files
- Share interesting crash inputs via issues

### Q: How do I add my own fuzz target?

**A:** Create a new file in `targets/`:

```python
# targets/fuzz_myfeature.py
import atheris
import sys

def TestOneInput(data):
    try:
        my_function(data)
    except ValueError:
        pass  # Expected error
    except Exception as e:
        raise  # Unexpected - might be a bug!

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

Update `run_fuzzing.py` to include your target.

---

## Next Steps

Now that you've mastered the basics:

1. **Read the full README:** `cat README.md`
2. **Study the fuzz targets:** `ls targets/`
3. **Learn property-based testing:** https://hypothesis.readthedocs.io/
4. **Explore The Fuzzing Book:** https://www.fuzzingbook.org/
5. **Set up CI/CD fuzzing:** See `.github/workflows/fuzzing.yml`

---

## Cheat Sheet

```bash
# List all targets
python run_fuzzing.py --list

# Quick property tests (30 seconds)
python run_fuzzing.py --target property

# Fuzz dataset parser (5 minutes)
python run_fuzzing.py --target dataset --duration 300

# Fuzz test case models (5 minutes)
python run_fuzzing.py --target testcase --duration 300

# Run all targets (1 hour)
python run_fuzzing.py --target all --duration 3600

# Verbose output (see what's happening)
python run_fuzzing.py --target dataset --duration 300 --verbose

# Check for crashes
ls crashes/

# View crash details
cat crashes/crash_*.txt
```

---

## Troubleshooting

### "Module not found" errors

Make sure the virtual environment is activated:
```bash
source ../.venv-fuzzing/bin/activate  # macOS/Linux
..\.venv-fuzzing\Scripts\Activate.ps1  # Windows
```

### "Permission denied" on macOS/Linux

Make scripts executable:
```bash
chmod +x deploy_macos.sh
chmod +x run_fuzzing.py
```

### Slow fuzzing performance

1. Close other applications
2. Use a simpler target first (`property`)
3. Check if antivirus is interfering
4. Reduce corpus size

### No crashes found

This is actually good! It means the code is robust. But you can:
- Run for longer (more time = more coverage)
- Add more complex seed inputs
- Try different targets

---

## Success Metrics

After your first fuzzing session, you should have:

- ✅ Installed fuzzing tools
- ✅ Run at least one fuzzing campaign
- ✅ Understood the output metrics
- ✅ Checked for crashes
- ✅ Learned about property-based testing

**Congratulations!** You're now a fuzzing practitioner! 🎉

---

## Get Help

- **Issues:** https://github.com/confident-ai/deepeval/issues
- **Documentation:** `README.md` in this directory
- **Learning:** https://www.fuzzingbook.org/

Happy bug hunting! 🐛🔍
