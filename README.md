# litellm-check

Scan local Python environments for malicious `litellm` installs and leftover payload files.

An environment is treated as compromised when either of these conditions is true:

- `litellm` is installed at version `1.82.7` or `1.82.8`
- `litellm_init.pth` is present in the environment's `site-packages`

The scanner also checks uv caches for `litellm_init.pth`.

## What It Scans

- System Python interpreters discovered from `PATH` and common install locations
- Conda environments
- Virtual environments found in common project and venv directories
- uv caches at:
  - `~/.cache/uv`
  - `~/Library/Caches/uv`
  - `UV_CACHE_DIR` if set

## Requirements

- Python 3.9+

No `pip` dependency is required for detection.

## Usage

Run the scanner:

```bash
./scan_malicious_litellm.py
```

Print JSON output:

```bash
./scan_malicious_litellm.py --json
```

Add extra directories to search for virtual environments:

```bash
./scan_malicious_litellm.py --root ~
./scan_malicious_litellm.py --root ~/Workspace --root ~/Projects
```

## Output

The script reports:

- Number of environments scanned
- Number of environments with `litellm` installed
- Number of malicious version hits
- Number of environments with leftover `litellm_init.pth`
- uv cache hits for `litellm_init.pth`

Exit codes:

- `0`: no malicious version or leftover payload detected
- `1`: at least one compromised environment or uv cache hit detected

## Example

```text
Environments scanned: 27
Environments with litellm installed: 0
Malicious version hits: 0
Environments with leftover litellm_init.pth: 0
uv cache hits for litellm_init.pth: 0

Verdict: no 1.82.7 / 1.82.8 detected
```

## Notes

- The scanner uses Python's `importlib.metadata` instead of `pip`.
- A leftover `litellm_init.pth` is treated as compromise even if `litellm` was later upgraded or removed.
- Broken or incomplete environments may still be scanned as long as their Python interpreter starts.
