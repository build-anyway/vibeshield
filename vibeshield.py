import ast
import re
import sys
import os
import argparse

SECRET_PATTERNS = [
    (r"sk_live_", "Stripe live key"),
    (r"sk_test_", "Stripe test key"),
    (r"sk-[a-zA-Z0-9]+", "OpenAI key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"(postgres|postgresql|mongodb|mysql)://[^:]+:[^@]+@", "Database URI with credentials")
]

TARGET_FUNCS = {
    ('os', 'system'),
    ('os', 'popen'),
    ('subprocess', 'Popen'),
    ('subprocess', 'run'),
    ('subprocess', 'call'),
    ('subprocess', 'check_output'),
    ('subprocess', 'check_call'),
}

class Finding:
    def __init__(self, line, rule, description):
        self.line = line
        self.rule = rule
        self.description = description

    def __str__(self):
        return f"Line {self.line}: [{self.rule}] {self.description}"

def is_exempt(val):
    if isinstance(val, ast.Call):
        func = val.func
        if isinstance(func, ast.Attribute):
            # os.environ.get("KEY")
            if func.attr == 'get' and isinstance(func.value, ast.Attribute) and \
               func.value.attr == 'environ' and isinstance(func.value.value, ast.Name) and \
               func.value.value.id == 'os':
                return True
            # os.getenv("KEY")
            if func.attr == 'getenv' and isinstance(func.value, ast.Name) and func.value.id == 'os':
                return True
    if isinstance(val, ast.Subscript):
        # os.environ["KEY"] or os.environ['KEY']
        if isinstance(val.value, ast.Attribute) and val.value.attr == 'environ' and \
           isinstance(val.value.value, ast.Name) and val.value.value.id == 'os':
            return True
    return False

class VibeShieldVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self.skip_nodes = set()

    def _register_exemptions(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                self.skip_nodes.add(id(child))

    def visit_Assign(self, node):
        if is_exempt(node.value):
            self._register_exemptions(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value and is_exempt(node.value):
            self._register_exemptions(node)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and id(node) not in self.skip_nodes:
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, node.value):
                    self.findings.append(Finding(node.lineno, "Rule 1", f"Secrets Detection - {desc} found in string literal"))
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        func_path = []

        while isinstance(func, ast.Attribute):
            func_path.insert(0, func.attr)
            func = func.value

        if isinstance(func, ast.Name):
            func_path.insert(0, func.id)
        else:
            func_path = None

        if func_path and tuple(func_path) in TARGET_FUNCS:
            arg = None
            if node.args:
                arg = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg in ('args', 'cmd', 'command'):
                        arg = kw.value
                        break

            if arg:
                if isinstance(arg, ast.JoinedStr):
                    self.findings.append(Finding(node.lineno, "Rule 2", "Command Injection - Call to subprocess/os with f-string"))
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    self.findings.append(Finding(node.lineno, "Rule 2", "Command Injection - Call to subprocess/os with string concatenation"))

        if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
            self.findings.append(Finding(node.lineno, "Rule 3", f"eval/exec Detection - Call to {node.func.id}()"))

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        is_lazy = True
        if len(node.body) == 0:
            is_lazy = False

        for stmt in node.body:
            if isinstance(stmt, ast.Pass):
                continue
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
                continue
            is_lazy = False
            break

        if is_lazy:
            self.findings.append(Finding(node.lineno, "Rule 4", "Lazy Exception - Exception handler is empty (pass or ...)"))

        self.generic_visit(node)

def scan_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            src = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}")
        return [Finding(0, "Error", "File not found")]
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return [Finding(0, "Error", str(e))]

    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        print(f"{filepath} - SyntaxError: {e}")
        return [Finding(e.lineno or 0, "SyntaxError", str(e))]

    visitor = VibeShieldVisitor()
    visitor.visit(tree)
    return visitor.findings

def install_hook():
    if not os.path.isdir('.git/hooks'):
        print("Error: Not a git repository (.git/hooks not found)")
        sys.exit(1)

    hook_path = '.git/hooks/pre-commit'

    if os.path.exists(hook_path):
        with open(hook_path, 'r', encoding='utf-8') as f:
            existing_content = f.read()
        if "vibeshield.py" in existing_content:
            print("Pre-commit hook is already installed.")
            return

    script_abs_path = os.path.abspath(sys.argv[0])

    hook_content = f"""#!/bin/sh
# VibeShield pre-commit hook
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\\.py$')
if [ -n "$FILES" ]; then
    echo "$FILES" | tr '\\n' '\\0' | xargs -0 python "{script_abs_path}"
    if [ $? -ne 0 ]; then
        echo "VibeShield found vulnerabilities. Commit aborted."
        exit 1
    fi
fi
exit 0
"""
    mode = 'a' if os.path.exists(hook_path) else 'w'
    with open(hook_path, mode, encoding='utf-8') as f:
        if mode == 'a':
            f.write("\n")
        f.write(hook_content)

    os.chmod(hook_path, 0o755)
    print(f"Pre-commit hook successfully configured at {hook_path}")

def main():
    parser = argparse.ArgumentParser(description="VibeShield - AI-generated Python code security scanner")
    parser.add_argument('files', nargs='*', help='Python files to scan')
    parser.add_argument('--install-hook', action='store_true', help='Install a git pre-commit hook to scan staged files')
    args = parser.parse_args()

    if args.install_hook:
        install_hook()
        sys.exit(0)

    all_findings = []
    for f in args.files:
        findings = scan_file(f)
        for finding in findings:
            print(f"{f} - {finding}")
            all_findings.append(finding)

    if all_findings:
        sys.exit(1)
    sys.exit(0)

if __name__ == '__main__':
    main()
