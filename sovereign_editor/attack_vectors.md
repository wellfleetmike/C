# Attack Vectors

This document catalogues the specific Unicode patterns the scanner detects, what each one looks like, and how attackers use it. Read it when you need to understand a particular detection or extend the scanner with a new vector.

The scanner classifies findings into the vector labels listed below. A single codepoint can carry multiple labels -- for example, U+E0041 is both a tag block character and a Cf-category character. The classification is descriptive, not exclusive.

## Zero-width characters

**Codepoints:** U+200B (zero-width space), U+200C (zero-width non-joiner), U+200D (zero-width joiner), U+200E (left-to-right mark), U+200F (right-to-left mark), U+2060 (word joiner), U+FEFF (zero-width no-break space, also used as byte order mark).

**What it looks like:** Nothing. By definition, zero-width characters have no glyph and no width when rendered. A user reading the text on screen sees no indication that they are present.

**How attackers use it:** As fingerprints, separators in encoded payloads, and to defeat string-equality checks. A username `admin` and a username `ad\u200Bmin` are different strings but look identical on screen. Zero-width joiners and non-joiners can also alter how surrounding characters render in some fonts, enabling display-time deception.

**Why the scanner flags it:** Always suspicious. There is no legitimate reason for a zero-width character to appear in code, configuration, or operator notes. Text rendering does not need them. The only reason they end up in a file is either an editor bug or a deliberate insertion.

## Variation selectors

**Codepoints:** U+FE00 through U+FE0F (variation selectors 1-16), U+E0100 through U+E01EF (variation selectors 17-256).

**What it looks like:** Variation selectors are non-visible modifiers that follow a base character and select an alternate glyph variant. The most familiar example is U+FE0F, which forces emoji presentation on a character that would otherwise render as text. To a user reading plain text, variation selectors are invisible.

**How attackers use it:** As steganographic carriers. The 256 supplementary variation selectors (U+E0100-U+E01EF) are particularly useful because they exist in a contiguous range and can encode arbitrary 8-bit data by mapping each byte value to one selector. A long message can be hidden by appending a sequence of selectors after an innocuous base character. The base character renders normally; the selectors render as nothing.

**Why the scanner flags it:** Same logic as zero-width. Code, configuration, and operator notes have no legitimate need for variation selectors. They are almost always either decorative emoji presentation or hidden payloads.

## Tag block

**Codepoints:** U+E0000 through U+E007F.

**What it looks like:** Nothing. The tag block was originally added to Unicode for language tagging in plain text. It was deprecated for that purpose and most renderers do not display it. The block contains 128 codepoints that map one-to-one with the lower ASCII range -- U+E0041 corresponds to ASCII 'A', U+E0061 to ASCII 'a', and so on. Each tag character is the invisible twin of its ASCII counterpart.

**How attackers use it:** Two ways. First, as a covert channel: an attacker can write a string in tag characters that decodes one-to-one to a human-readable message, but the message is invisible when rendered. Second, against AI systems that have been trained on text containing tag characters: the model may associate tag characters with the meanings of their ASCII counterparts and follow instructions delivered in tag form even when those instructions are invisible to the human operator. This is the mechanism described in the Pillar Security Claude Tags injection disclosure.

**Why the scanner flags it:** Tag characters have effectively zero legitimate use cases in modern text. If they are in a file, they are almost certainly either a steganographic payload or a prompt injection.

## Private Use Area

**Codepoints:** U+E000 through U+F8FF (basic PUA), U+F0000 through U+FFFFD (supplementary PUA-A), U+100000 through U+10FFFD (supplementary PUA-B).

**What it looks like:** Depends on font. The Private Use Area is reserved by the Unicode standard for non-standardized characters used by specific applications or fonts. Some fonts assign glyphs to specific PUA codepoints, so the character may render as anything -- a custom icon, a corporate logo glyph, or nothing at all if no font on the system has a glyph assigned.

**How attackers use it:** As payload carriers, similar to the tag block. The PUA is large -- over 130,000 codepoints across the three blocks -- and the entire space is available for steganographic encoding. PUA characters are also useful for evading content filters because rendering systems do not have consistent expectations about them.

**Why the scanner flags it:** Sovereign infrastructure should not contain PUA codepoints. If text needs a custom glyph, the legitimate path is a font with a properly-assigned codepoint outside the PUA. PUA in a file is a sign that either the file is using a private encoding the operator should know about, or the file is contaminated.

## Mathematical alphanumeric symbols

**Codepoints:** U+1D400 through U+1D7FF.

**What it looks like:** Mathematical-style letters. The block contains styled variants of the Latin and Greek alphabets -- bold, italic, bold-italic, script, fraktur, double-struck, sans-serif, sans-serif bold, monospace. Each style has its own range. To a reader, a mathematical bold capital A (U+1D400) looks like a styled A. To a string-comparison tool, it is a completely different codepoint from ASCII 'A' (U+0041).

**How attackers use it:** As homoglyph substitution against string-equality checks. A function call to `print` and a function call to `\U0001D429rint` (mathematical bold lowercase p followed by 'rint') look almost identical to the human eye but route through different code paths. Mathematical alphanumeric is also useful for evading keyword filters that look for specific ASCII words.

**Why the scanner flags it:** Same logic as homoglyphs. Code and configuration should use ASCII. Any styled letter in a file where ASCII is expected is a substitution.

## Non-standard whitespace

**Codepoints:** U+00A0 (no-break space), U+2000-U+200A (various widths of space), U+202F (narrow no-break space), U+205F (medium mathematical space), U+2028 (line separator), U+2029 (paragraph separator), U+3000 (ideographic space).

**What it looks like:** Whitespace. To the eye, indistinguishable from ASCII space (U+0020). To a parser, completely different characters that may or may not be treated as whitespace depending on the parser's whitespace definition.

**How attackers use it:** To defeat parsing-based defenses. A shell command like `rm -rf /` is dangerous; the same string with a U+00A0 instead of the ASCII space after `rm` may either be rejected by the shell (because the parser doesn't treat U+00A0 as a word separator) or accepted (because some shells do). Either outcome can be the attack: if rejected, the command appears safe; if accepted, the command runs while looking like it shouldn't have.

**Why the scanner flags it:** Operator notes and code should use ASCII space. There is rarely a legitimate reason for non-standard whitespace in sovereign infrastructure.

## Control characters

**Codepoints:** U+0000 through U+0008, U+000B, U+000C, U+000E through U+001F, U+007F through U+009F. The whitelist explicitly allows U+0009 (tab), U+000A (newline), and U+000D (carriage return), so those are excluded from this vector.

**What it looks like:** Depends on the terminal or editor. Some control characters have no visible effect. Others trigger terminal escape sequences (cursor movement, color changes, screen clearing). U+0007 (bell) makes the terminal beep. U+001B (escape) is the lead-in for ANSI escape sequences which can perform arbitrary terminal manipulations.

**How attackers use it:** Terminal escape sequence injection. If text containing escape sequences is printed to a terminal, the terminal will obey the sequences. An attacker can use this to write data to the user's clipboard, move the cursor, set the window title to something misleading, or even (on some terminals) inject keystrokes into the shell. The CVE record on terminal injection attacks is long.

**Why the scanner flags it:** Control characters outside the three allowed structural ones should never appear in code, configuration, or notes. They are either accidental garbage from a corrupted file or deliberate injection.

## Homoglyphs

**Codepoints:** A small curated set of Cyrillic and Greek letters that look identical to ASCII letters. See `HOMOGLYPH_MAP` in `contamination_scanner.py` for the current list. Common entries include U+0430 (Cyrillic a), U+0435 (Cyrillic e), U+043E (Cyrillic o), U+0440 (Cyrillic p), U+0441 (Cyrillic c), U+0443 (Cyrillic y), U+03BF (Greek omicron).

**What it looks like:** Identical to the ASCII letter it impersonates. The Cyrillic small letter a (U+0430) is visually indistinguishable from ASCII 'a' (U+0061) in nearly every font.

**How attackers use it:** Phishing against URLs and identifier-matching against package names, usernames, and command names. A registered package whose name appears to be `requests` but where one of the letters is actually a Unicode lookalike (for example, Cyrillic small letter es U+0441 in place of ASCII 'c') can sit alongside the legitimate `requests` package and look identical in a search result or copy-paste. The same trick works against `npm install` and similar package managers.

**Why the scanner flags it:** The homoglyph map is short and focused on the most common attacker substitutions. The scanner does not claim to detect every possible homoglyph -- that would require a complete Unicode confusable-character database, which is a separate project. The scanner does flag the high-value patterns and gives the operator a starting point.

## Extending the scanner

To add a new attack vector, edit `ATTACK_VECTORS` in `contamination_scanner.py`. Each entry is a tuple of (label, predicate), where the predicate takes a codepoint integer and returns True if the codepoint matches the vector. After adding the vector, add a corresponding entry to `ATTACK_VECTORS` in `self_test.py` with a codepoint that triggers the new predicate, then rerun the self-test to confirm detection.

The whitelist itself lives in one place: `ALLOWED_CODEPOINTS` at the top of each script. Changes to the whitelist must be propagated to all three scripts (scanner, editor, clipboard watcher). The duplication is intentional -- each script is meant to be deployable standalone, so the whitelist definition is repeated rather than imported.
