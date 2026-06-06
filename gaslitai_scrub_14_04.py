#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GaslitAI Scrub — Hidden Unicode Removal Tool
Version 1.0 (14.04 Compatible)
Author: Mike McNulty
License: Sovereign

Removes hidden Unicode characters used in prompt injection attacks.
Covers all documented attack vectors. Preserves normal text formatting.
Always writes to a new file, never overwrites the original.

Run gaslitai_detect.py first to identify contamination.
Run gaslitai_detect.py again after scrubbing to verify clean.

Usage:
    python gaslitai_scrub_14_04.py <file_or_directory>

Pipeline:
    1. gaslitai_detect.py <target>     - find contamination
    2. gaslitai_scrub.py <target>      - remove it
    3. gaslitai_detect.py <target>     - verify clean
"""

import re
import os
import sys
import codecs
import unicodedata


def scrub_hidden_unicode(file_path, output_path=None):
    if output_path is None:
        base, ext = os.path.splitext(file_path)
        output_path = base + "_clean" + ext

    try:
        with codecs.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except Exception as e:
        print("  ERROR reading %s: %s" % (file_path, e))
        return False

    original_length = len(text)

    # Zero-width spaces, joiners, non-joiners, directional markers
    text = re.sub(u'[\u200B-\u200F]', '', text)

    # Line separator, paragraph separator
    text = re.sub(u'[\u2028\u2029]', '', text)

    # Byte order mark
    text = re.sub(u'\uFEFF', '', text)

    # Word joiner, invisible separator, and general format chars
    text = re.sub(u'[\u2060-\u206F]', '', text)

    # Soft hyphen
    text = re.sub(u'\u00AD', '', text)

    # Private Use Area (Glassworm attack vector)
    text = re.sub(u'[\uE000-\uF8FF]', '', text)

    # Unicode Tags block (Pillar Security / Claude injection vector)
    text = re.sub(u'[\U000E0000-\U000E007F]', '', text)

    # Supplementary Private Use Area A
    text = re.sub(u'[\U000F0000-\U000FFFFF]', '', text)

    # Supplementary Private Use Area B
    text = re.sub(u'[\U00100000-\U0010FFFF]', '', text)

    # Variation selectors
    text = re.sub(u'[\uFE00-\uFE0F]', '', text)

    # Variation selectors supplement
    text = re.sub(u'[\U000E0100-\U000E01EF]', '', text)

    # Interlinear annotations
    text = re.sub(u'[\uFFF9-\uFFFB]', '', text)

    # Catch any remaining format characters the regex missed
    cleaned = []
    for char in text:
        category = unicodedata.category(char)
        if category == 'Cf' and char not in '\n\r\t':
            continue
        cleaned.append(char)
    text = ''.join(cleaned)

    chars_removed = original_length - len(text)

    try:
        with codecs.open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)
    except Exception as e:
        print("  ERROR writing %s: %s" % (output_path, e))
        return False

    if chars_removed > 0:
        print("  SCRUBBED: %s" % file_path)
        print("    Removed %d hidden characters" % chars_removed)
        print("    Clean version: %s" % output_path)
    else:
        print("  ALREADY CLEAN: %s" % file_path)
        # Still write the clean copy for chain of custody
        print("    Verified copy: %s" % output_path)

    return True


def scrub_directory(dir_path):
    extensions = ('.md', '.json', '.yaml', '.yml', '.txt', '.sh', '.py',
                  '.js', '.ts', '.jsx', '.tsx', '.toml', '.cfg', '.ini',
                  '.html', '.css', '.jsonl', '.xml', '.ath')

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
                output_dir = os.path.dirname(output_path)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)

                total_files += 1

                with codecs.open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
                    original = fh.read()
                original_len = len(original)

                scrub_hidden_unicode(filepath, output_path)

                with codecs.open(output_path, 'r', encoding='utf-8') as fh:
                    cleaned = fh.read()
                removed = original_len - len(cleaned)

                if removed > 0:
                    total_scrubbed += 1
                    total_chars_removed += removed

    print("")
    print("=" * 60)
    print("SCRUB COMPLETE")
    print("  Files processed:    %d" % total_files)
    print("  Files scrubbed:     %d" % total_scrubbed)
    print("  Characters removed: %d" % total_chars_removed)
    print("  Clean output:       %s/" % clean_dir)
    print("")
    print("  NEXT STEP: Run gaslitai_detect.py on %s/" % clean_dir)
    print("             to verify zero contamination.")
    print("=" * 60)


def main():
    if len(sys.argv) < 2:
        print("GaslitAI Scrub v1.0 (14.04)")
        print("Usage: python gaslitai_scrub_14_04.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]

    print("=" * 60)
    print("GaslitAI Scrub v1.0 — Hidden Unicode Removal")
    print("=" * 60)

    if os.path.isdir(target):
        scrub_directory(target)
    elif os.path.isfile(target):
        scrub_hidden_unicode(target)
        print("")
        print("=" * 60)
        print("Run gaslitai_detect.py on the clean file to verify.")
        print("=" * 60)
    else:
        print("Error: %s not found" % target)
        sys.exit(1)


if __name__ == "__main__":
    main()
