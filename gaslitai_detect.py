#!/usr/bin/env python3
"""
GaslitAI Detect — Hidden Unicode Scanner
Version 1.0
Author: Mike McNulty
License: Sovereign

Scans files for hidden Unicode characters used in prompt injection
attacks against AI coding tools. Covers all documented attack vectors
including zero-width characters, directional markers, Private Use Area,
and the Unicode Tags block (CVE-2025-59536 / Pillar Security).

Usage:
    python gaslitai_detect.py <file_or_directory>
"""

import unicodedata
import os
import sys


def detect_hidden_unicode(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except Exception as e:
        print(f"  ERROR reading {file_path}: {e}")
        return 0

    suspicious = []
    for i, char in enumerate(text):
        code_point = ord(char)
        category = unicodedata.category(char)
        name = unicodedata.name(char, "UNKNOWN")

        # Control characters and format characters (excluding normal whitespace)
        if category.startswith(('Cf', 'Cc', 'Cs', 'Co')) and char not in '\n\r\t':
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))

        # Zero-width and directional characters
        elif 0x200B <= code_point <= 0x200F:
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))

        # Line/paragraph separators (non-standard)
        elif code_point in (0x2028, 0x2029):
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))

        # Byte order mark
        elif code_point == 0xFEFF:
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))

        # General format characters
        elif 0x2060 <= code_point <= 0x206F:
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))

        # Private Use Area (Glassworm attack vector)
        elif 0xE000 <= code_point <= 0xF8FF:
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))

        # Unicode Tags block (Pillar Security / Claude injection vector)
        elif 0xE0000 <= code_point <= 0xE007F:
            suspicious.append((i, char, name, f"U+{code_point:06X}", category))

        # Supplementary Private Use Areas
        elif 0xF0000 <= code_point <= 0x10FFFF:
            suspicious.append((i, char, name, f"U+{code_point:06X}", category))

    if suspicious:
        print(f"\n  CONTAMINATED: {file_path}")
        print(f"  Found {len(suspicious)} hidden Unicode characters:")
        for pos, char, name, code, cat in suspicious[:100]:
            context_start = max(0, pos - 20)
            context_end = min(len(text), pos + 20)
            context = text[context_start:context_end].replace('\n', ' ')
            print(f"    Pos {pos}: {code} [{cat}] {name}")
            print(f"      Context: ...{context}...")
        if len(suspicious) > 100:
            print(f"    ... and {len(suspicious) - 100} more")
    else:
        print(f"  CLEAN: {file_path}")

    return len(suspicious)


def scan_directory(dir_path):
    extensions = ('.md', '.json', '.yaml', '.yml', '.txt', '.sh', '.py',
                  '.js', '.ts', '.jsx', '.tsx', '.toml', '.cfg', '.ini',
                  '.html', '.css', '.jsonl', '.xml')
    total_files = 0
    total_contaminated = 0
    total_hidden = 0

    for root, dirs, files in os.walk(dir_path):
        # Skip node_modules and .git
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__')]
        for f in files:
            if f.endswith(extensions):
                filepath = os.path.join(root, f)
                total_files += 1
                count = detect_hidden_unicode(filepath)
                if count > 0:
                    total_contaminated += 1
                    total_hidden += count

    print(f"\n{'=' * 60}")
    print(f"SCAN COMPLETE")
    print(f"  Files scanned: {total_files}")
    print(f"  Contaminated:  {total_contaminated}")
    print(f"  Hidden chars:  {total_hidden}")
    if total_contaminated == 0:
        print(f"  Status:        ALL CLEAN")
    else:
        print(f"  Status:        CONTAMINATION FOUND — run gaslitai_scrub.py")
    print(f"{'=' * 60}")


def main():
    if len(sys.argv) < 2:
        print("GaslitAI Detect v1.0")
        print("Usage: python gaslitai_detect.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]

    print("=" * 60)
    print("GaslitAI Detect v1.0 — Hidden Unicode Scanner")
    print("=" * 60)

    if os.path.isdir(target):
        scan_directory(target)
    elif os.path.isfile(target):
        count = detect_hidden_unicode(target)
        print(f"\n{'=' * 60}")
        if count == 0:
            print("Status: CLEAN")
        else:
            print(f"Status: {count} HIDDEN CHARACTERS FOUND")
        print(f"{'=' * 60}")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)


if __name__ == "__main__":
    main()
