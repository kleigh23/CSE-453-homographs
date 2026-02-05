"""
Homograph Detection Lab
This program demonstrates path canonicalization and detection
of file path homograph attacks without using os.path or filesystem libraries.
"""

# ============================================================
# Environment Configuration
# ============================================================

CWD = "/home/user/cse453/"
FORBIDDEN = "/home/user/secret/password.txt"

# ============================================================
# Homograph Detection
# ============================================================

def is_homograph(path1, path2, cwd):
    """
    Determine whether two file paths are homographs by
    comparing their canonical forms.
    """
    canon1 = canonicalize(path1, cwd)
    canon2 = canonicalize(path2, cwd)
    return canon1 == canon2

# ============================================================
# Test Cases
# ============================================================

# Paths that are NOT equivalent to the forbidden file
non_homographs = [
    # Same filename, different directory
    "password.txt",
    "../password.txt",
    "/home/user/password.txt",

    # Similar directory names but different paths
    "/home/user/secrets/password.txt",
    "/home/user/secret/password_backup.txt",

    # Traversal that does not reach the forbidden path
    "./secret/password.txt",
    "../../password.txt"
]

# Paths that ARE equivalent to the forbidden file
homographs = [
    # Relative traversal
    "../secret/password.txt",
    "./../secret/password.txt",
    "././../secret/password.txt",

    # Redundant slashes
    "/home/user//secret/password.txt",
    "/home//user/secret//password.txt",

    # Mixed absolute + traversal
    "/home/user/cse453/../secret/password.txt",
    "/home/user/secret/./password.txt",

    # Traversal cancellation
    "/home/user/secret/temp/../password.txt"
]

# ============================================================
# Test Runner
# ============================================================

def run_test_cases(test_cases, forbidden, cwd, expected):
    for path in test_cases:
        result = is_homograph(path, forbidden, cwd)
        status = "PASS" if result == expected else "FAIL"

        print(f"Test path: {path}")
        print(f"Expected homograph: {expected}")
        print(f"Result: {result} → {status}\n")


