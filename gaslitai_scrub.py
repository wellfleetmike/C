#!/usr/bin/env python3
"""
GaslitAI Scrub — Hidden Unicode Removal Tool
Version 1.0
Author: Mike McNulty
License: Sovereign

Removes hidden Unicode characters used in prompt injection attacks.
Covers all documented attack vectors. Preserves normal text formatting.
Always writes to a new file, never overwrites the original.

Run gaslitai_detect.py first to identify contamination.
Run gaslitai_detect.py again after scrubbing to verify clean.

Usage:
    python gaslitai_scrub.py <file_or_directory>

Pipeline:
    1. gaslitai_detect.py <target>     — find contamination
    2. gaslitai_scrub.py <target>      — remove it
    3. gaslitai_detect.py <target>     — verify clean
"""

import re
import os
import sys
import unicodedata


def scrub_hidden_unicode(file_path, output_path=None):
    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_clean{ext}"

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except Exception as e:
        print(f"  ERROR reading {file_path}: {e}")
        return False

    original_length = len(text)

    # Zero-width spaces, joiners, non-joiners, directional markers
    text = re.sub(r'[\u200B-\u200F]', '', text)

    # Line separator, paragraph separator
    text = re.sub(r'[\u2028\u2029]', '', text)

    # Byte order mark
    text = re.sub(r'\uFEFF', '', text)

    # Word joiner, invisible separator, and general format chars
    text = re.sub(r'[\u2060-\u206F]', '', text)

    # Soft hyphen
    text = re.sub(r'\u00AD', '', text)

    # Private Use Area (Glassworm attack vector)
    text = re.sub(r'[\uE000-\uF8FF]', '', text)

    # Unicode Tags block (Pillar Security / Claude injection vector)
    text = re.sub(r'[\U000E0000-\U000E007F]', '', text)

    # Supplementary Private Use Area A
    text = re.sub(r'[\U000F0000-\U000FFFFF]', '', text)

    # Supplementary Private Use Area B
    text = re.sub(r'[\U00100000-\U0010FFFF]', '', text)

    # Variation selectors
    text = re.sub(r'[\uFE00-\uFE0F]', '', text)

    # Variation selectors supplement
    text = re.sub(r'[\U000E0100-\U000E01EF]', '', text)

    # Interlinear annotations
    text = re.sub(r'[\uFFF9-\uFFFB]', '', text)

    # Catch any remaining format characters the regex missed
    cleaned = []
    for char in text:
        category = unicodedata.category(char)
        if category in ('Cf', 'Cc') and char not in '\n\r\t':
            continue
        cleaned.append(char)
    text = ''.join(cleaned)

    chars_removed = original_length - len(text)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)
    except Exception as e:
        print(f"  ERROR writing {output_path}: {e}")
        return False

    if chars_removed > 0:
        print(f"  SCRUBBED: {file_path}")
        print(f"    Removed {chars_removed} hidden characters")
        print(f"    Clean version: {output_path}")
    else:
        print(f"  ALREADY CLEAN: {file_path}")
        # Still write the clean copy for chain of custody
        print(f"    Verified copy: {output_path}")

    return True


def scrub_directory(dir_path):
    extensions = ('.md', '.json', '.yaml', '.yml', '.txt', '.sh', '.py',
                  '.js', '.ts', '.jsx', '.tsx', '.toml', '.cfg', '.ini',
                  '.html', '.css', '.jsonl', '.xml')

    # Create clean output directory
    clean_dir = dir_path.rstrip('/') + '_clean'
    total_files = 0
    total_scrubbed = 0
    total_chars_removed = 0

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git', '__pycache__')]
        for f in files:
            if f.endswith(extensions):
                filepath = os.path.join(root, f)
                # Mirror directory structure in clean output
                relative = os.path.relpath(filepath, dir_path)
                output_path = os.path.join(clean_dir, relative)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                total_files += 1

                with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
                    original = fh.read()
                original_len = len(original)

                scrub_hidden_unicode(filepath, output_path)

                with open(output_path, 'r', encoding='utf-8') as fh:
                    cleaned = fh.read()
                removed = original_len - len(cleaned)

                if removed > 0:
                    total_scrubbed += 1
                    total_chars_removed += removed

    print(f"\n{'=' * 60}")
    print(f"SCRUB COMPLETE")
    print(f"  Files processed:    {total_files}")
    print(f"  Files scrubbed:     {total_scrubbed}")
    print(f"  Characters removed: {total_chars_removed}")
    print(f"  Clean output:       {clean_dir}/")
    print(f"")
    print(f"  NEXT STEP: Run gaslitai_detect.py on {clean_dir}/")
    print(f"             to verify zero contamination.")
    print(f"{'=' * 60}")


def main():
    if len(sys.argv) < 2:
        print("GaslitAI Scrub v1.0")
        print("Usage: python gaslitai_scrub.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]

    print("=" * 60)
    print("GaslitAI Scrub v1.0 — Hidden Unicode Removal")
    print("=" * 60)

    if os.path.isdir(target):
        scrub_directory(target)
    elif os.path.isfile(target):
        scrub_hidden_unicode(target)
        print(f"\n{'=' * 60}")
        print(f"Run gaslitai_detect.py on the clean file to verify.")
        print(f"{'=' * 60}")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)


if __name__ == "__main__":
    main()
