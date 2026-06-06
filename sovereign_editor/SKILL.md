---
name: sovereign-editor
description: A contamination-resistant text editing and scanning toolkit for the threat model where AI-generated content carries hidden Unicode payloads -- homoglyphs, variation selectors, zero-width characters, tag block steganography (U+E0000-E007F), private use area insertions, mathematical alphanumeric substitutions, and non-standard whitespace. Use this skill whenever the user is reviewing, editing, transferring, or sanitizing text that originated from an LLM or any untrusted source before it lands on sovereign or air-gapped infrastructure. Triggers include any mention of Unicode contamination, hidden payloads in text, Claude-generated content review, Glassworm-style supply chain attacks, prompt injection via invisible characters, clipboard sanitization, or paste-safety. Also use when the user describes "scanning a file for hidden characters," "checking what's in this paste," "stripping non-printable characters," or building an air-gapped editing workflow.
---

# Sovereign Editor

A whitelist-enforcing text editor, forensic scanner, clipboard interceptor, and self-test harness for defending hand-typed and reviewed text against hidden Unicode payloads. Built for the operator who treats every paste from an LLM as potentially contaminated and refuses to let unverified bytes touch sovereign infrastructure.

## When to use this skill

Use this skill whenever the user is about to transfer text that originated from an LLM, a web page, or any untrusted source onto a system they care about. Use it when the user mentions reviewing AI-generated code or configuration before pasting it onto an air-gapped node. Use it when the user describes scanning a file for invisible characters, hidden payloads, or "what's actually in this text." Use it when the user is building a workflow that needs paste-safety guarantees.

The skill is also the right tool when the user wants to understand what attack vectors exist in this category, what published disclosures cover them, or how to test a detection tool against known patterns.

## The whitelist

The editor and scanner enforce one rule: a file or buffer may contain only the 98 characters of printable ASCII (U+0020 through U+007E, which is 95 characters) plus tab (U+0009), newline (U+000A), and carriage return (U+000D). Anything outside that set is flagged, marked, or refused.

This is a deliberately narrow whitelist. It will reject characters that humans use legitimately -- accented letters, em-dashes, curly quotes, emoji. The premise is that on sovereign infrastructure used for code, configuration, and operator notes, plain ASCII is sufficient and any character outside it deserves a human decision before it lands. The editor visualizes rather than silently strips, so the operator stays in the loop.

## What's in this skill

The skill ships with four scripts under `scripts/`, two reference documents under `references/`, and a contamination sample under `assets/`. The scripts are designed to run independently -- each one solves a piece of the problem and can be invoked from the command line. The editor, scanner, and clipboard watcher are not coupled; they share the same whitelist definition but otherwise stand alone.

- `scripts/sovereign_editor.py` is a curses-based text editor that enforces the whitelist on every keystroke, renders any non-whitelist character in a loaded file as a visible marker showing the codepoint, and provides paste-with-sanitization and paste-with-visualization as separate commands bound to different keys.
- `scripts/contamination_scanner.py` is a forensic scanner. It takes any file as input and produces both a JSON report and a human-readable report listing every non-whitelist character with byte offset, line and column, codepoint, Unicode category, Unicode name, and forty characters of surrounding context.
- `scripts/clipboard_watch.py` is a clipboard interceptor that polls the system clipboard via xclip, xsel, or wl-paste -- whichever is installed -- and warns before any paste action when non-whitelist content is present. It is a standing-by tool, not a hook into the OS clipboard at the kernel level.
- `scripts/self_test.py` is a self-test harness that generates a deliberately contaminated test file with one example of each known attack vector, then invokes the scanner and verifies that every vector is detected. Use it to verify the toolkit is working and to demonstrate detection capability.

## How to use the scripts

The scanner is the right first move on any file the user wants to review:

```
python3 scripts/contamination_scanner.py <path-to-file> --format text
python3 scripts/contamination_scanner.py <path-to-file> --format json > report.json
```

The editor opens a file (or starts an empty buffer) and enforces the whitelist as the user types or pastes:

```
python3 scripts/sovereign_editor.py <path-to-file>
```

Inside the editor, Ctrl-S saves, Ctrl-X exits, Ctrl-V pastes-with-sanitization (strips non-whitelist), Ctrl-B pastes-with-visualization (inserts markers so the operator can see what arrived), and arrow keys navigate.

The clipboard watcher runs in a terminal as a standing process:

```
python3 scripts/clipboard_watch.py
```

It prints a warning every time clipboard contents change and contain non-whitelist characters, including the codepoints found.

The self-test harness generates the contamination sample, runs the scanner against it, and verifies each attack vector is detected:

```
python3 scripts/self_test.py
```

## References

`references/threat_model.md` explains why this skill exists, what the attacker is trying to do, and what published disclosures motivate the work. It covers Glassworm (Koi Security, October 2025) and the Pillar Security Claude Tags injection. Read it when the user wants the threat-model framing or wants to know what to cite.

`references/attack_vectors.md` is a catalogue of the specific Unicode patterns the scanner detects, with codepoint ranges, what they look like to a human, and how they are used in attacks. Read it when the user wants to understand a specific detection or extend the scanner with a new vector.

## Reading order

When invoked, read `references/threat_model.md` first to ground in why each design choice exists, then `references/attack_vectors.md` if the user is asking about specific patterns. The scripts have inline comments and can be read directly if the user wants to verify what they do before running them on real data.

## Constraints

The skill uses only the Python 3 standard library. There are no pip dependencies. It runs offline. The clipboard interceptor requires one of xclip, xsel, or wl-paste to be installed on the host -- these are system utilities, not Python packages, and they are standard on most Linux desktops. The editor uses Python's built-in curses module and works in any terminal that supports curses.

Treat any contamination report or scrub output the way you would treat any other tool output: as a finding to be reviewed by the operator, not as a permission to paste. The whole point of the toolkit is to keep the human in the verification loop.
