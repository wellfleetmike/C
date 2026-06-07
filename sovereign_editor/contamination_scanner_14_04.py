#!/usr/bin/env python3
"""
contamination_scanner_14_04.py
==============================

Python 3.4-compatible backport of contamination_scanner.py. Same whitelist,
same attack vectors, same homoglyph map, same output format. The only
differences are syntactic:

  * No f-strings (Python 3.6+) -- uses str.format() instead.
  * No pathlib.Path.read_text() (Python 3.5+) -- uses open() instead.
  * No other 3.5+ features.

Target: stock Python 3.4 on Ubuntu 14.04. Use this on offline boxes that
cannot upgrade Python. The modern contamination_scanner.py is preferred
everywhere else.

The whitelist is intentionally narrow: printable ASCII (U+0020 through
U+007E inclusive, which is 95 characters), tab (U+0009), newline (U+000A),
and carriage return (U+000D). Total of 98 allowed characters. Everything
else is flagged.

No external dependencies. Python 3.4 standard library only.
"""

import argparse
import json
import os
import sys
import unicodedata


# The whitelist. Printable ASCII (0x20-0x7E) plus tab, newline, CR.
ALLOWED_CODEPOINTS = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# Attack-vector classification ranges. Same as the modern scanner.
ATTACK_VECTORS = [
    ("zero_width",
     lambda cp: cp in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x2060)),
    ("variation_selector",
     lambda cp: 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF),
    ("tag_block",
     lambda cp: 0xE0000 <= cp <= 0xE007F),
    ("private_use_basic",
     lambda cp: 0xE000 <= cp <= 0xF8FF),
    ("private_use_supplementary",
     lambda cp: 0xF0000 <= cp <= 0xFFFFD or 0x100000 <= cp <= 0x10FFFD),
    ("mathematical_alphanumeric",
     lambda cp: 0x1D400 <= cp <= 0x1D7FF),
    ("non_standard_whitespace",
     lambda cp: cp in (0x00A0, 0x202F, 0x205F, 0x3000) or
                0x2000 <= cp <= 0x200A or
                0x2028 <= cp <= 0x2029),
    ("control_character",
     lambda cp: (cp < 0x20 and cp not in (0x09, 0x0A, 0x0D)) or
                (0x7F <= cp <= 0x9F)),
]


HOMOGLYPH_MAP = {
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0443: "y",
    0x0445: "x",
    0x0410: "A",
    0x0415: "E",
    0x041E: "O",
    0x03BF: "o",
    0x03BC: "u",
    0x0391: "A",
    0x0392: "B",
    0x0395: "E",
    0x039F: "O",
}


def classify_codepoint(cp):
    labels = []
    for label, predicate in ATTACK_VECTORS:
        if predicate(cp):
            labels.append(label)
    if cp in HOMOGLYPH_MAP:
        labels.append("homoglyph")
    return labels


def get_unicode_name(cp):
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return "<no name; category {0}>".format(unicodedata.category(chr(cp)))


def get_context(text, position, width=20):
    start = max(0, position - width)
    end = min(len(text), position + width + 1)
    rendered = []
    for i in range(start, end):
        cp = ord(text[i])
        if cp in ALLOWED_CODEPOINTS:
            if cp == 0x0A:
                rendered.append("\\n")
            elif cp == 0x09:
                rendered.append("\\t")
            elif cp == 0x0D:
                rendered.append("\\r")
            else:
                rendered.append(text[i])
        else:
            rendered.append("[U+{0:04X}]".format(cp))
    return "".join(rendered)


def scan_text(text):
    findings = []
    line = 1
    col = 1
    byte_offset = 0
    for char_offset, ch in enumerate(text):
        cp = ord(ch)
        if cp not in ALLOWED_CODEPOINTS:
            findings.append({
                "char_offset": char_offset,
                "byte_offset": byte_offset,
                "line": line,
                "column": col,
                "codepoint_dec": cp,
                "codepoint_hex": "U+{0:04X}".format(cp),
                "category": unicodedata.category(ch),
                "name": get_unicode_name(cp),
                "vectors": classify_codepoint(cp),
                "homoglyph_target": HOMOGLYPH_MAP.get(cp),
                "context": get_context(text, char_offset, 20),
            })
        if ch == "\n":
            line += 1
            col = 1
        else:
            col += 1
        byte_offset += len(ch.encode("utf-8"))
    return findings


def render_text_report(file_path, findings, total_chars):
    out = []
    out.append("Contamination scan report")
    out.append("File: {0}".format(file_path))
    out.append("Total characters scanned: {0}".format(total_chars))
    out.append("Non-whitelist characters found: {0}".format(len(findings)))
    out.append("")
    if not findings:
        out.append("No contamination detected. File is whitelist-clean.")
        return "\n".join(out)
    for i, f in enumerate(findings, 1):
        out.append("Finding #{0}".format(i))
        out.append("  Position:  line {0}, column {1} "
                   "(char offset {2}, byte offset {3})".format(
                       f['line'], f['column'],
                       f['char_offset'], f['byte_offset']))
        out.append("  Codepoint: {0} ({1} decimal)".format(
            f['codepoint_hex'], f['codepoint_dec']))
        out.append("  Category:  {0}".format(f['category']))
        out.append("  Name:      {0}".format(f['name']))
        if f["vectors"]:
            out.append("  Vectors:   {0}".format(", ".join(f['vectors'])))
        else:
            out.append("  Vectors:   (none classified -- uncategorized non-whitelist)")
        if f["homoglyph_target"]:
            out.append("  Lookalike: appears as ASCII '{0}'".format(
                f['homoglyph_target']))
        out.append("  Context:   {0}".format(f['context']))
        out.append("")
    return "\n".join(out)


def render_json_report(file_path, findings, total_chars):
    return json.dumps({
        "file": str(file_path),
        "total_characters": total_chars,
        "finding_count": len(findings),
        "clean": len(findings) == 0,
        "findings": findings,
    }, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a file for Unicode characters outside the "
                    "printable-ASCII whitelist. Python 3.4-compatible.")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--encoding", default="utf-8",
                        help="File encoding (default: utf-8)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        sys.stderr.write("Error: {0} is not a readable file\n".format(args.file))
        sys.exit(2)

    with open(args.file, "r", encoding=args.encoding, errors="replace") as fh:
        text = fh.read()

    findings = scan_text(text)
    if args.format == "json":
        print(render_json_report(args.file, findings, len(text)))
    else:
        print(render_text_report(args.file, findings, len(text)))

    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
