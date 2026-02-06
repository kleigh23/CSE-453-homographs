"""
Homograph Detection Lab

Authors: Nicholas Wilkins, Kelley Robertson, Kyle Davies, and Cecelia Pendell
Class: CSE 453 - Computer Security
Date: February 5th, 2026

Description:
Detects homographs in file paths without using os.path or pathlib. Provides
canonicalization, homograph checks, test cases, and manual input.
"""

# ============================================================
# Canonicalization
# ============================================================

def canonicalize(path, cwd):
    '''
    Returns the canonical form of path using cwd as the base for relative paths.
     - Splits path into raw_parts and resolves "." and ".." while iterating.
     - For absolute paths, starts clean_parts at root.
     - For relative paths, initializes clean_parts from cwd.
     - Builds clean_parts, popping on "..", and joins with "/".
    '''
    if path[:1] == "/":
        clean_parts = []
        raw_parts = path.split("/")
    else:
        clean_parts = cwd.strip("/").split("/")
        raw_parts = path.split("/")

    for raw_part in raw_parts:
        if raw_part == "" or raw_part == ".":
            continue
        elif raw_part == "..":
            if clean_parts:
                clean_parts.pop()
        else:
            clean_parts.append(raw_part)

    return "/" + "/".join(clean_parts)

# ============================================================
# Homograph Detection
# ============================================================

def is_homograph(path1, path2, cwd):
    '''
    Returns True when path1 and path2 canonicalize to the same value under cwd.
    '''
    canon1 = canonicalize(path1, cwd)
    canon2 = canonicalize(path2, cwd)
    return canon1 == canon2

# ============================================================
# Test Runner
# ============================================================

def run_test_cases(test_cases, forbidden, cwd, expected):
    '''
    Runs test_cases against forbidden and prints pass/fail based on expected.
    '''
    for path in test_cases:
        result = is_homograph(path, forbidden, cwd)
        status = "PASS" if result == expected else "FAIL"

        print(f"Test path: {path}")
        print(f"Expected homograph: {expected}")
        print(f"Result: {result} | Status: {status}\n")

# ============================================================
# Manual Test Execution
# ============================================================

def manual_testing_mode(cwd):
    '''
    Prompts for two paths and prints whether they are homographs under cwd.
    '''
    print(f"\nDefault Working Directory: {cwd}")
    path1 = input("Enter the first path to test: ").strip()
    path2 = input("Enter the second path to test: ").strip()

    result = is_homograph(path1, path2, cwd)
    print(f"\nAre the two paths homographs? {result}\n")

# ============================================================
# Test Cases
# ============================================================

# Not equivalent to the forbidden file
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

# Equivalent to the forbidden file
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
# Environment Configuration
# ============================================================

CWD = "/home/user/cse453/"
FORBIDDEN = "/home/user/secret/password.txt"

# ============================================================
# Main Execution
# ============================================================
def main():
    print("\nWelcome to the Path Homograph Detection Lab!\n")
    running = True
    while running:
        print("Select an option:")
        print("1. Run Automated Test Cases")
        print("2. Manual Homograph Testing Mode")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")
        choice = choice.strip()

        if choice == "1":
            print("\nRunning Non-Homograph Test Cases:")
            run_test_cases(non_homographs, FORBIDDEN, CWD, expected=False)

            print("\nRunning Homograph Test Cases:")
            run_test_cases(homographs, FORBIDDEN, CWD, expected=True)

        elif choice == "2":
            manual_testing_mode(CWD)

        elif choice == "3":
            print("\nExiting the program. Goodbye!\n")
            running = False

        else:
            print("Invalid choice. Please enter 1, 2, or 3.\n")

if __name__ == "__main__":
    main()