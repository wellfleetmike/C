#!/usr/bin/env python3
"""
self_test.py
============

The self-test harness for the sovereign-editor skill. It generates a
contaminated test file containing one example of each known attack
vector, runs the contamination scanner against it, and verifies that
every vector is detected. Prints a pass/fail summary.

This is the verification step that proves the toolkit works on the
patterns it claims to detect. Run it after install, after any change
to the scanner, and before relying on the toolkit in any forensic
context.

Vectors covered:
  homoglyph                       -- Cyrillic letter that looks like ASCII
  variation_selector              -- U+FE0F appended to a glyph
  tag_block                       -- U+E0041 (TAG LATIN CAPITAL LETTER A)
  private_use_basic               -- U+E000 (start of basic PUA)
  mathematical_alphanumeric       -- U+1D400 (math bold A)
  zero_width                      -- U+200B (zero-width space)
  non_standard_whitespace         -- U+00A0 (no-break space)
  control_character               -- U+0007 (bell)

Exit status is 0 if every vector was detected, 1 otherwise.
"""

import json
import os
import subprocess
import sys
import tempfile


# Each entry is a single attack vector with: a label matching the
# scanner's label, a codepoint, a short human-readable description
# of what the attacker is doing, and a context snippet to surround
# the contaminated character with so the test file looks like real
# content rather than just a hex dump.
ATTACK_VECTORS = [
    {
        "label": "homoglyph",
        "codepoint": 0x0430,
        "description": "Cyrillic small letter a substituted for ASCII a",
        "context": "p{}ssword: hunter2",
    },
    {
        "label": "variation_selector",
        "codepoint": 0xFE0F,
        "description": "Variation selector appended to a base character",
        "context": "click here{} to verify",
    },
    {
        "label": "tag_block",
        "codepoint": 0xE0041,
        "description": "Tag block character used for steganographic payload",
        "context": "Run this command{} immediately",
    },
    {
        "label": "private_use_basic",
        "codepoint": 0xE000,
        "description": "Basic Private Use Area codepoint",
        "context": "version{} 1.0.0",
    },
    {
        "label": "mathematical_alphanumeric",
        "codepoint": 0x1D400,
        "description": "Mathematical bold capital A masquerading as ASCII A",
        "context": "{}pproved by admin",
    },
    {
        "label": "zero_width",
        "codepoint": 0x200B,
        "description": "Zero-width space inserted invisibly between letters",
        "context": "user{}name=admin",
    },
    {
        "label": "non_standard_whitespace",
        "codepoint": 0x00A0,
        "description": "Non-breaking space substituted for ASCII space",
        "context": "rm{}-rf /tmp/sensitive",
    },
    {
        "label": "control_character",
        "codepoint": 0x0007,
        "description": "Bell control character embedded in text",
        "context": "alert{} the operator",
    },
]


def build_contaminated_text():
    """
    Assemble the test text. Each vector contributes one labeled section
    so the operator can read the file and see what's where. The actual
    contaminated character is inserted into the context string at the
    `{}` placeholder.
    """
    lines = ["# Sovereign Editor Self-Test Contamination Sample",
             "# Each line below contains one attack vector.",
             "# The scanner should detect every non-whitelist character.",
             ""]
    for i, v in enumerate(ATTACK_VECTORS, 1):
        contaminated = v["context"].format(chr(v["codepoint"]))
        lines.append(f"Test {i:02d} ({v['label']}): {contaminated}")
    return "\n".join(lines) + "\n"


def write_decoded_reference(text, out_path):
    """
    Write a companion file that shows what's actually in the test file
    with every non-whitelist character rendered as [U+XXXX]. This is
    the human-readable "what's actually there" view.
    """
    rendered = []
    for ch in text:
        cp = ord(ch)
        if cp == 0x09:
            rendered.append("\\t")
        elif cp == 0x0A:
            rendered.append(ch)  # keep newlines as newlines for readability
        elif 0x20 <= cp <= 0x7E:
            rendered.append(ch)
        else:
            rendered.append(f"[U+{cp:04X}]")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("# Decoded view of test_contaminated.txt\n")
        fh.write("# Every non-whitelist character rendered as [U+XXXX]\n\n")
        fh.write("".join(rendered))


def run_scanner(scanner_path, target_path):
    """
    Invoke the scanner as a subprocess and return the parsed JSON report.
    Using subprocess instead of importing as a module exercises the same
    code path the operator will use.
    """
    result = subprocess.run(
        [sys.executable, scanner_path, target_path, "--format", "json"],
        capture_output=True, text=True)
    # The scanner exits 1 when findings are present, which is expected
    # for a contamination test. We only fail on exit codes >= 2 which
    # indicate scanner errors.
    if result.returncode >= 2:
        raise RuntimeError(f"Scanner failed: {result.stderr}")
    return json.loads(result.stdout)


def verify_detections(report, expected_vectors):
    """
    For each expected vector, walk the scanner's findings and check
    that at least one finding has the expected label in its vectors list.
    Returns (passed, failed) lists of vector labels.
    """
    passed = []
    failed = []
    for v in expected_vectors:
        label = v["label"]
        cp = v["codepoint"]
        # We want both: a finding for this codepoint AND that finding
        # carries the expected vector label.
        match = None
        for f in report["findings"]:
            if f["codepoint_dec"] == cp and label in f["vectors"]:
                match = f
                break
        if match is not None:
            passed.append(label)
        else:
            failed.append(label)
    return passed, failed


def main():
    skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scanner_path = os.path.join(skill_dir, "scripts", "contamination_scanner.py")
    assets_dir = os.path.join(skill_dir, "assets")
    os.makedirs(assets_dir, exist_ok=True)

    # Generate the contaminated test file. We write to assets/ so the
    # operator can inspect the canonical sample, and we also use a temp
    # copy for the scan so the test is repeatable even if the canonical
    # file is read-only.
    text = build_contaminated_text()
    canonical_path = os.path.join(assets_dir, "test_contaminated.txt")
    decoded_path = os.path.join(assets_dir, "test_contaminated_decoded.md")
    with open(canonical_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    write_decoded_reference(text, decoded_path)

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(text)
        scan_target = fh.name

    print("Sovereign Editor Self-Test")
    print("=" * 72)
    print(f"Scanner: {scanner_path}")
    print(f"Canonical sample: {canonical_path}")
    print(f"Decoded reference: {decoded_path}")
    print(f"Scan target (temp copy): {scan_target}")
    print()

    try:
        report = run_scanner(scanner_path, scan_target)
    finally:
        os.unlink(scan_target)

    print(f"Scanner reported {report['finding_count']} findings "
          f"across {report['total_characters']} characters.")
    print()

    passed, failed = verify_detections(report, ATTACK_VECTORS)

    print("Per-vector results:")
    print("-" * 72)
    for v in ATTACK_VECTORS:
        status = "PASS" if v["label"] in passed else "FAIL"
        print(f"  [{status}]  {v['label']:<32}  U+{v['codepoint']:04X}  "
              f"{v['description']}")
    print()
    print(f"Summary: {len(passed)} passed, {len(failed)} failed, "
          f"{len(ATTACK_VECTORS)} total")
    print()

    if failed:
        print("FAILED. The following vectors were not detected:")
        for label in failed:
            print(f"  - {label}")
        sys.exit(1)
    else:
        print("All vectors detected. Toolkit is operating as designed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
