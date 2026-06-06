#!/usr/bin/env python3
"""
clipboard_watch.py
==================

A clipboard interceptor. Polls the system clipboard at a fixed interval
and warns the operator whenever the clipboard contents change and the
new contents contain any non-whitelist character. The intent is to be
a standing-by tool -- run it in a terminal window while you work, and
it will tell you when something dangerous has just been copied into
your clipboard, so you know before you paste.

Strategy: poll, hash, compare. We don't have a hook into the OS
clipboard at the kernel level (that would be platform-specific and
require root or special permissions on most systems), so we poll on
a tunable interval and compare the new contents to a stored hash of
the last contents. If they differ, we scan the new contents and emit
a warning if non-whitelist characters are present.

Clipboard access goes through xclip, xsel, or wl-paste -- whichever is
installed. The watcher exits with a clear error message if none of
those utilities is available.

No external dependencies. Python 3 standard library only.
"""

import argparse
import hashlib
import subprocess
import sys
import time
import unicodedata


# Same whitelist as the scanner and editor.
ALLOWED_CODEPOINTS = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def detect_clipboard_tool():
    """
    Return the command list for the first available clipboard read tool,
    or None if none of xclip, xsel, wl-paste are installed.
    """
    candidates = [
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste", "--no-newline"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            # A successful return code with no stderr complaining about
            # X server or wayland means the utility is installed and
            # functional. Empty clipboard is a normal zero-return result.
            if result.returncode == 0:
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def read_clipboard(cmd):
    """Run the clipboard-read command and return contents as a string."""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=2)
        return result.stdout.decode("utf-8", errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def find_contamination(text):
    """
    Walk the text and return a list of (codepoint, category, name) tuples
    for every non-whitelist character. Used to build the warning message.
    """
    findings = []
    for ch in text:
        cp = ord(ch)
        if cp not in ALLOWED_CODEPOINTS:
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "<unnamed>"
            findings.append((cp, unicodedata.category(ch), name))
    return findings


def format_warning(text, findings):
    """Build a human-readable warning block for the terminal."""
    lines = []
    lines.append("")
    lines.append("=" * 72)
    lines.append("CLIPBOARD WARNING: non-whitelist characters detected")
    lines.append("=" * 72)
    lines.append(f"Clipboard size: {len(text)} characters")
    lines.append(f"Contaminated characters: {len(findings)}")
    # Group by codepoint for a compact summary.
    seen = {}
    for cp, cat, name in findings:
        if cp not in seen:
            seen[cp] = {"count": 0, "category": cat, "name": name}
        seen[cp]["count"] += 1
    lines.append("")
    lines.append("Codepoint distribution:")
    for cp in sorted(seen.keys()):
        info = seen[cp]
        lines.append(f"  U+{cp:04X}  count={info['count']:<4}  "
                     f"cat={info['category']}  {info['name']}")
    lines.append("")
    lines.append("Do not paste into sovereign infrastructure without "
                 "reviewing or sanitizing.")
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Watch the system clipboard for non-whitelist content.")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Polling interval in seconds (default: 1.0)")
    parser.add_argument("--quiet-on-clean", action="store_true",
                        help="Suppress messages when clipboard is clean")
    args = parser.parse_args()

    cmd = detect_clipboard_tool()
    if cmd is None:
        print("Error: no clipboard read utility found. Install one of:",
              file=sys.stderr)
        print("  xclip, xsel, or wl-paste", file=sys.stderr)
        sys.exit(2)

    print(f"Clipboard watcher running. Polling every {args.interval}s.")
    print(f"Using: {' '.join(cmd)}")
    print("Press Ctrl-C to stop.")
    print()

    last_hash = None
    try:
        while True:
            text = read_clipboard(cmd)
            # Hash the contents so we only act when they change. This
            # avoids spamming the operator with repeated warnings about
            # the same clipboard payload that's been sitting there.
            current_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if current_hash != last_hash:
                last_hash = current_hash
                findings = find_contamination(text)
                if findings:
                    print(format_warning(text, findings))
                elif not args.quiet_on_clean and text:
                    print(f"[clean] clipboard updated, "
                          f"{len(text)} chars, no contamination")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nClipboard watcher stopped.")


if __name__ == "__main__":
    main()
