#!/usr/bin/env python3
"""
contamination_scanner.py
========================

Forensic scanner that walks every codepoint in a file and reports every
character outside the allowed whitelist. Output is either a human-readable
text report or structured JSON for programmatic consumption.

The whitelist is intentionally narrow: printable ASCII (U+0020 through
U+007E inclusive, which is 95 characters), tab (U+0009), newline (U+000A),
and carriage return (U+000D). Total of 98 allowed characters. Everything
else is flagged.

Why so narrow? Because on sovereign infrastructure used for code,
configuration, and operator notes, the legitimate need for non-ASCII is
near zero, and any non-ASCII character is a potential carrier for a
hidden payload. The scanner is deliberately blunt -- it finds every
character outside the whitelist and lets the operator decide what to do.

No external dependencies. Python 3.6+ standard library only.
"""

import argparse
import json
import sys
import unicodedata
from pathlib import Path


# The whitelist. Printable ASCII (0x20-0x7E) plus tab, newline, CR.
# Defined as a set of integer codepoints for fast membership testing.
ALLOWED_CODEPOINTS = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# Attack-vector classification ranges. A codepoint can fall into more
# than one of these (e.g., a tag character is both Cf and in the tag
# block), so we test each range and collect every label that applies.
# Each tuple is (label, predicate). The predicate takes a codepoint
# integer and returns True if the codepoint matches the vector.
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


# Known homoglyph mappings. Each tuple is (suspect_codepoint, ascii_lookalike).
# This list is intentionally short -- exhaustive homoglyph detection is a
# separate research project. The entries here are the most common ones used
# in phishing and supply-chain attacks against package names and identifiers.
# An empty match here doesn't mean the character is safe -- only that we
# don't have a specific homoglyph claim for it.
HOMOGLYPH_MAP = {
    0x0430: "a",  # Cyrillic small letter a
    0x0435: "e",  # Cyrillic small letter ie
    0x043E: "o",  # Cyrillic small letter o
    0x0440: "p",  # Cyrillic small letter er
    0x0441: "c",  # Cyrillic small letter es
    0x0443: "y",  # Cyrillic small letter u
    0x0445: "x",  # Cyrillic small letter ha
    0x0410: "A",  # Cyrillic capital letter A
    0x0415: "E",  # Cyrillic capital letter Ie
    0x041E: "O",  # Cyrillic capital letter O
    0x03BF: "o",  # Greek small letter omicron
    0x03BC: "u",  # Greek small letter mu (looks like u)
    0x0391: "A",  # Greek capital letter Alpha
    0x0392: "B",  # Greek capital letter Beta
    0x0395: "E",  # Greek capital letter Epsilon
    0x039F: "O",  # Greek capital letter Omicron
}


def classify_codepoint(cp):
    """
    Return a list of attack-vector labels that apply to this codepoint.
    A single codepoint can carry multiple labels (e.g., U+E0041 is both
    a tag_block character and a Cf category character). Empty list means
    the codepoint is non-whitelist but doesn't match any specific known
    vector -- still suspicious, just uncategorized.
    """
    labels = []
    for label, predicate in ATTACK_VECTORS:
        if predicate(cp):
            labels.append(label)
    if cp in HOMOGLYPH_MAP:
        labels.append("homoglyph")
    return labels


def get_unicode_name(cp):
    """
    Return the official Unicode name for the codepoint, or a fallback
    string if unicodedata has no name on record (which is true for many
    private use and unassigned codepoints).
    """
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        return f"<no name; category {unicodedata.category(chr(cp))}>"


def get_context(text, position, width=20):
    """
    Return up to `width` characters before and after `position`, with
    non-whitelist characters rendered as a visible marker so the report
    is readable even when the contamination is invisible. The visible
    marker is [U+XXXX] in plain text so it survives copy-paste into other
    tools without further mangling.
    """
    start = max(0, position - width)
    end = min(len(text), position + width + 1)
    rendered = []
    for i in range(start, end):
        cp = ord(text[i])
        if cp in ALLOWED_CODEPOINTS:
            # Render newlines and tabs visibly so the offset relationship
            # in the context stays readable.
            if cp == 0x0A:
                rendered.append("\\n")
            elif cp == 0x09:
                rendered.append("\\t")
            elif cp == 0x0D:
                rendered.append("\\r")
            else:
                rendered.append(text[i])
        else:
            rendered.append(f"[U+{cp:04X}]")
    return "".join(rendered)


def scan_text(text):
    """
    Walk every codepoint in `text` and return a list of finding dicts,
    one per non-whitelist character. Each finding has byte offset (in
    UTF-8 encoding of the file), character offset, line, column, codepoint
    in both decimal and hex form, Unicode category, Unicode name, attack
    vector labels, the ASCII lookalike if a homoglyph match was found,
    and the surrounding context.
    """
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
                "codepoint_hex": f"U+{cp:04X}",
                "category": unicodedata.category(ch),
                "name": get_unicode_name(cp),
                "vectors": classify_codepoint(cp),
                "homoglyph_target": HOMOGLYPH_MAP.get(cp),
                "context": get_context(text, char_offset, 20),
            })
        # Advance line/column counters. The newline check has to come
        # before the column bump or column will be wrong on the line after.
        if ch == "\n":
            line += 1
            col = 1
        else:
            col += 1
        # Track byte offset using UTF-8 encoding length.
        byte_offset += len(ch.encode("utf-8"))
    return findings


def render_text_report(file_path, findings, total_chars):
    """
    Produce a human-readable text report. Format is one finding per
    paragraph with a header line and indented detail lines. Designed
    to read cleanly in a terminal and to survive copy-paste into a
    notes file without losing structure.
    """
    out = []
    out.append(f"Contamination scan report")
    out.append(f"File: {file_path}")
    out.append(f"Total characters scanned: {total_chars}")
    out.append(f"Non-whitelist characters found: {len(findings)}")
    out.append("")
    if not findings:
        out.append("No contamination detected. File is whitelist-clean.")
        return "\n".join(out)
    for i, f in enumerate(findings, 1):
        out.append(f"Finding #{i}")
        out.append(f"  Position:  line {f['line']}, column {f['column']} "
                   f"(char offset {f['char_offset']}, byte offset {f['byte_offset']})")
        out.append(f"  Codepoint: {f['codepoint_hex']} ({f['codepoint_dec']} decimal)")
        out.append(f"  Category:  {f['category']}")
        out.append(f"  Name:      {f['name']}")
        if f["vectors"]:
            out.append(f"  Vectors:   {', '.join(f['vectors'])}")
        else:
            out.append(f"  Vectors:   (none classified -- uncategorized non-whitelist)")
        if f["homoglyph_target"]:
            out.append(f"  Lookalike: appears as ASCII '{f['homoglyph_target']}'")
        out.append(f"  Context:   {f['context']}")
        out.append("")
    return "\n".join(out)


def render_json_report(file_path, findings, total_chars):
    """
    Produce a JSON report suitable for programmatic consumption. Keys
    are stable across runs so downstream tools can rely on them.
    """
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
                    "printable-ASCII whitelist.")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--encoding", default="utf-8",
                        help="File encoding (default: utf-8)")
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"Error: {file_path} is not a readable file", file=sys.stderr)
        sys.exit(2)

    # Read with errors="replace" so we don't crash on malformed bytes;
    # any replacement character that appears will itself be flagged
    # because U+FFFD is outside the whitelist.
    text = file_path.read_text(encoding=args.encoding, errors="replace")

    findings = scan_text(text)
    if args.format == "json":
        print(render_json_report(file_path, findings, len(text)))
    else:
        print(render_text_report(file_path, findings, len(text)))

    # Exit code 0 if clean, 1 if findings present. This lets the scanner
    # be used in shell pipelines and pre-commit hooks.
    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
