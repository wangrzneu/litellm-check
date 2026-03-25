# Linux Environment Test Report

## Environment

- **OS**: Linux 6.18.5 x86_64 GNU/Linux
- **Python**: Python 3.11.14
- **Date**: 2026-03-25

## Test Results

### Text Mode (`./scan_malicious_litellm.py`)

- Exit code: **0** (clean)
- Environments scanned: **9**
- Environments with litellm installed: **0**
- Malicious version hits: **0**
- Environments with leftover `litellm_init.pth`: **0**
- uv cache hits for `litellm_init.pth`: **0**
- Verdict: **no 1.82.7 / 1.82.8 detected**

### JSON Mode (`./scan_malicious_litellm.py --json`)

- Produces valid JSON output
- `compromised` field: `false`
- All 9 environments scanned without errors

### Detected Python Interpreters

| Interpreter | Path |
|---|---|
| python3 | /usr/local/bin/python3 |
| python3.10 | /bin/python3.10, /usr/bin/python3.10 |
| python3.11 | /bin/python3.11, /usr/bin/python3.11 |
| python3.12 | /bin/python3.12, /usr/bin/python3.12 |
| python3.13 | /bin/python3.13, /usr/bin/python3.13 |

## Summary

The scanner runs correctly on Linux. It successfully:

1. Discovered 9 system Python interpreters (3.10 through 3.13)
2. Checked each environment for malicious litellm versions
3. Checked for leftover `litellm_init.pth` files
4. Checked uv cache directories
5. Produced correct text and JSON output
6. Returned exit code 0 (no compromise detected)
