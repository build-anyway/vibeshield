# VibeShield 🛡️

A lightweight, single-file, zero-dependency Python CLI utility designed to run in resource-constrained local environments (like Termux or local VS Code) to intercept high-risk patterns *before* they are committed to GitHub.

It parses the native Abstract Syntax Tree (AST) using Python's standard library to bypass heavy package compilation blocks.

## Core Protections

1. **Strict Secret Scrubbing:** Scans for obvious exposed key structures (Stripe, OpenAI, AWS, and database connection strings). Exempts assignments loaded via `os.environ` or `os.getenv`.
2. **AST Command Injection Auditing:** Flags unsafe f-strings or string concatenations inside execution calls (`os.system`, `subprocess.run`, etc.).
3. **eval/exec Prevention:** Flags all instances of raw dynamic code evaluation.
4. **Lazy Exception Alert:** Flags empty `except: pass` blocks which AI models frequently use to quietly swallow execution failures.

## Install

```bash
git clone https://github.com/build-anyway/vibeshield.git
cd vibeshield
```

## Usage

```bash
# Scan a specific file manually
python vibeshield.py path/to/file.py

# Install as a Git pre-commit hook in your local repository
python vibeshield.py --install-hook
