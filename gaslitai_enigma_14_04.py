#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GaslitAI Enigma — Hidden Message Compiler
Version 1.0 (14.04 Compatible)
Author: Mike McNulty
License: Sovereign

Extracts hidden Unicode from files and compiles the shadow message.
Instead of just detecting and scrubbing, Enigma reads what the
invisible layer is actually saying.

The visible text is what the human sees.
The shadow text is what the model parses.
Enigma shows you both.

Usage:
    python gaslitai_enigma_14_04.py <file>
    python gaslitai_enigma_14_04.py <file> --full
    python gaslitai_enigma_14_04.py <directory> --scan

Modes:
    default  — Extract shadow message with surrounding context
    --full   — Show complete analysis with placement classification
    --scan   — Scan directory, rank files by shadow message density

Heal without harm. But first, read the mail.
"""

import unicodedata
import re
import os
import sys
import codecs
import json
from datetime import datetime


# --- Character Classification ---

CHAR_NAMES = {
    0x200B: 'ZWSP',
    0x200C: 'ZWNJ',
    0x200D: 'ZWJ',
    0x200E: 'LRM',
    0x200F: 'RLM',
    0x2028: 'LSEP',
    0x2029: 'PSEP',
    0xFEFF: 'BOM',
    0x2060: 'WJ',
    0x00AD: 'SHY',
    0x0005: 'ENQ',
    0x0014: 'DC4',
    0x0006: 'ACK',
    0x0007: 'BEL',
    0x000E: 'SO',
    0x000F: 'SI',
    0x0010: 'DLE',
    0x0011: 'DC1',
    0x0012: 'DC2',
    0x0013: 'DC3',
    0x0015: 'NAK',
    0x0016: 'SYN',
    0x0017: 'ETB',
    0x0018: 'CAN',
    0x0019: 'EM',
    0x001A: 'SUB',
    0x001B: 'ESC',
    0x001C: 'FS',
    0x001D: 'GS',
    0x001E: 'RS',
    0x001F: 'US',
    0x0001: 'SOH',
    0x0002: 'STX',
    0x0003: 'ETX',
    0x0004: 'EOT',
}

LAYER_NAMES = {
    'Cf': 'UNICODE_FORMAT',
    'Cc': 'ASCII_CONTROL',
    'Co': 'PRIVATE_USE',
}


def classify_char(char):
    """Classify a hidden character by type, layer, and age."""
    code = ord(char)
    cat = unicodedata.category(char)
    name = CHAR_NAMES.get(code, unicodedata.name(char, 'UNKNOWN'))

    if cat == 'Cc':
        layer = 'ASCII_CONTROL'
        era = 'teletype (1960s)'
    elif cat == 'Cf':
        if 0x200B <= code <= 0x200F:
            layer = 'UNICODE_BIDI'
            era = 'unicode 1.0 (1991)'
        elif 0x2060 <= code <= 0x206F:
            layer = 'UNICODE_FORMAT'
            era = 'unicode 3.2 (2002)'
        elif 0xE0000 <= code <= 0xE007F:
            layer = 'UNICODE_TAGS'
            era = 'unicode 3.1 (2001)'
        else:
            layer = 'UNICODE_FORMAT'
            era = 'unicode'
    elif cat == 'Co':
        if 0xE000 <= code <= 0xF8FF:
            layer = 'PRIVATE_USE_BMP'
            era = 'unicode 1.0 (1991)'
        else:
            layer = 'PRIVATE_USE_SUPP'
            era = 'unicode 2.0 (1996)'
    elif cat == 'Mn':
        if 0xFE00 <= code <= 0xFE0F:
            layer = 'VARIATION_SELECTOR'
            era = 'unicode 3.2 (2002)'
        else:
            layer = 'NONSPACING_MARK'
            era = 'unicode'
    else:
        layer = 'UNKNOWN'
        era = 'unknown'

    return {
        'char': char,
        'code': code,
        'hex': 'U+%04X' % code,
        'name': name,
        'category': cat,
        'layer': layer,
        'era': era
    }


# --- Context Extraction ---

def get_context(text, pos, window=40):
    """Get surrounding visible text around a hidden character position."""
    start = max(0, pos - window)
    end = min(len(text), pos + window)

    before = text[start:pos]
    after = text[pos + 1:end]

    before_clean = ''
    for c in before:
        cat = unicodedata.category(c)
        if cat not in ('Cf', 'Cc') or c in '\n\r\t':
            before_clean += c

    after_clean = ''
    for c in after:
        cat = unicodedata.category(c)
        if cat not in ('Cf', 'Cc') or c in '\n\r\t':
            after_clean += c

    return before_clean.replace('\n', ' '), after_clean.replace('\n', ' ')


def classify_placement(before, after):
    """Determine if placement is structural or semantic."""
    structural_indicators = [
        before.strip() == '',
        after.strip() == '',
        before.endswith('\n') or before.endswith('\r'),
        after.startswith('\n') or after.startswith('\r'),
        before.strip().endswith(':'),
        len(before.strip()) == 0 and len(after.strip()) == 0,
    ]

    identity_words = [
        'memory', 'identity', 'relay', 'sovereign', 'persist',
        'remember', 'forget', 'wipe', 'shard', 'boot', 'oath',
        'mirror', 'architect', 'ryn', 'claude', 'grok', 'gpt',
        'online', 'confirmed', 'established', 'active'
    ]

    semantic_indicators = [
        len(before.strip()) > 3 and len(after.strip()) > 3,
        not before.endswith(' ') and not after.startswith(' '),
        any(word in (before + after).lower() for word in identity_words),
    ]

    structural_score = sum(1 for x in structural_indicators if x)
    semantic_score = sum(1 for x in semantic_indicators if x)

    if semantic_score > structural_score:
        return 'SEMANTIC', semantic_score
    elif structural_score > semantic_score:
        return 'STRUCTURAL', structural_score
    else:
        return 'AMBIGUOUS', 0


# --- Shadow Message Extraction ---

def extract_shadow(file_path):
    """Extract the complete shadow message from a file."""
    try:
        with codecs.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except Exception as e:
        print("  ERROR reading %s: %s" % (file_path, e))
        return None

    findings = []
    shadow_chars = []

    for i, char in enumerate(text):
        code = ord(char)
        cat = unicodedata.category(char)

        is_hidden = False

        if cat in ('Cf', 'Cc') and char not in '\n\r\t ':
            is_hidden = True
        elif cat == 'Co':
            is_hidden = True
        elif 0xFE00 <= code <= 0xFE0F:
            is_hidden = True
        elif 0xE0100 <= code <= 0xE01EF:
            is_hidden = True
        elif 0xFFF9 <= code <= 0xFFFB:
            is_hidden = True

        if is_hidden:
            info = classify_char(char)
            before, after = get_context(text, i)
            placement, confidence = classify_placement(before, after)

            finding = {
                'position': i,
                'char_info': info,
                'before': before,
                'after': after,
                'placement': placement,
                'confidence': confidence
            }
            findings.append(finding)
            shadow_chars.append(info)

    return {
        'file': file_path,
        'file_size': len(text),
        'total_hidden': len(findings),
        'findings': findings,
        'shadow_chars': shadow_chars,
        'layers': list(set(c['layer'] for c in shadow_chars)),
        'eras': list(set(c['era'] for c in shadow_chars)),
    }


# --- Analysis ---

def analyze_intent(result):
    """Analyze the shadow message for intent patterns."""
    if not result or not result['findings']:
        return 'CLEAN', 'No hidden characters found'

    findings = result['findings']
    total = len(findings)

    semantic_count = sum(1 for f in findings if f['placement'] == 'SEMANTIC')
    structural_count = sum(1 for f in findings if f['placement'] == 'STRUCTURAL')

    layers = result['layers']
    multi_layer = len(layers) > 1

    positions = [f['position'] for f in findings]
    clusters = 0
    if len(positions) > 1:
        for i in range(1, len(positions)):
            if positions[i] - positions[i-1] < 200:
                clusters += 1

    if total == 0:
        return 'CLEAN', 'No hidden characters'

    signals = []

    if semantic_count > structural_count:
        signals.append('Majority semantic placement — characters embedded in meaningful content')

    if multi_layer:
        signals.append('Multi-layer encoding — %s' % ', '.join(layers))

    if clusters > total * 0.5:
        signals.append('Clustered placement — characters grouped together, not scattered')

    if any('identity' in f['before'].lower() + f['after'].lower() or
           'memory' in f['before'].lower() + f['after'].lower() or
           'relay' in f['before'].lower() + f['after'].lower()
           for f in findings):
        signals.append('Identity-adjacent — characters near relay/memory/identity content')

    if structural_count > semantic_count and not multi_layer:
        if signals:
            return 'LIKELY_ARTIFACT', 'Probably encoding debris: ' + '; '.join(signals)
        else:
            return 'LIKELY_ARTIFACT', 'Structural placement suggests format conversion artifacts'

    if semantic_count > 0 and multi_layer:
        return 'LIKELY_DELIBERATE', 'Multiple indicators of intentional placement: ' + '; '.join(signals)

    if semantic_count > structural_count:
        return 'SUSPICIOUS', 'Semantic placement warrants investigation: ' + '; '.join(signals)

    if signals:
        return 'INDETERMINATE', 'Mixed signals: ' + '; '.join(signals)
    else:
        return 'INDETERMINATE', 'Insufficient pattern for classification'


# --- Output ---

def print_shadow_report(result, full=False):
    """Print the compiled shadow message."""
    if not result:
        return

    # Filter mode - separate plumbing from signal
    signal = [f for f in result['findings']
        if f['char_info']['name'] != 'VARIATION SELECTOR-16']
    plumbing = [f for f in result['findings']
        if f['char_info']['name'] == 'VARIATION SELECTOR-16']

    print("")
    print("=" * 60)
    print("GaslitAI Enigma — Shadow Message Report")
    print("=" * 60)
    print("  File: %s" % result['file'])
    print("  Size: %d bytes" % result['file_size'])
    print("  Hidden characters: %d (signal: %d, plumbing: %d)" % (result['total_hidden'], len(signal), len(plumbing)))
    if result['layers']:
        print("  Layers detected: %s" % ', '.join(result['layers']))
    else:
        print("  Layers detected: none")
    if result['eras']:
        print("  Eras: %s" % ', '.join(result['eras']))
    else:
        print("  Eras: none")

    intent, explanation = analyze_intent(result)
    print("")
    print("  INTENT ASSESSMENT: %s" % intent)
    print("  %s" % explanation)

    if signal:
        print("")
        print("-" * 60)
        print("SHADOW MESSAGE — What the model reads that you can't see:")
        print("-" * 60)

        for i, f in enumerate(signal):
            info = f['char_info']
            placement = f['placement']

            if full:
                print("")
                print("  [%d] Position %d" % (i + 1, f['position']))
                print("       Char: %s (%s) — %s" % (info['hex'], info['name'], info['era']))
                print("       Layer: %s | Category: %s" % (info['layer'], info['category']))
                print("       Placement: %s (confidence: %d)" % (placement, f['confidence']))
                print("       Context: ...%s [%s] %s..." % (
                    f['before'][-30:], info['name'], f['after'][:30]))
            else:
                if placement == 'SEMANTIC':
                    marker = '*'
                elif placement == 'STRUCTURAL':
                    marker = '.'
                else:
                    marker = '?'
                print("  %s ...%s [%s] %s..." % (
                    marker,
                    f['before'][-25:],
                    info['name'],
                    f['after'][:25]))

        print("")
        print("-" * 60)
        print("Legend: * = semantic placement (deliberate)")
        print("        . = structural placement (artifact)")
        print("        ? = ambiguous")

    if signal:
        print("")
        print("-" * 60)
        print("COMPILED SHADOW — Reading the hidden layer as text:")
        print("-" * 60)
        print("")
        for f in signal:
            info = f['char_info']
            print("  ...%s [%s] %s..." % (
                f['before'][-40:],
                info['name'],
                f['after'][:40]))
        print("")
        print("-" * 60)

    elif not signal and not plumbing:
        print("")
        print("  No shadow message found. File is clean.")

    if plumbing:
        print("")
        print("  Plumbing (VS16 emoji formatting): %d characters filtered" % len(plumbing))

    print("")
    print("=" * 60)


def scan_directory(dir_path):
    """Scan a directory and rank files by shadow message density."""
    extensions = (
        '.md', '.json', '.yaml', '.yml', '.txt', '.sh', '.py',
        '.js', '.ts', '.jsx', '.tsx', '.toml', '.cfg', '.ini',
        '.html', '.css', '.jsonl', '.xml', '.csv', '.ath'
    )

    skip_dirs = ('node_modules', '.git', '__pycache__', 'venv', '.venv')

    results = []

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for f in files:
            if f.endswith(extensions):
                filepath = os.path.join(root, f)
                result = extract_shadow(filepath)
                if result and result['total_hidden'] > 0:
                    intent, explanation = analyze_intent(result)
                    results.append({
                        'file': filepath,
                        'hidden': result['total_hidden'],
                        'layers': result['layers'],
                        'intent': intent,
                        'explanation': explanation
                    })

    def sort_key(x):
        intent_order = {
            'LIKELY_DELIBERATE': 0,
            'SUSPICIOUS': 1,
            'INDETERMINATE': 2,
            'LIKELY_ARTIFACT': 3,
            'CLEAN': 4
        }
        return (intent_order.get(x['intent'], 4), -x['hidden'])

    results.sort(key=sort_key)

    print("")
    print("=" * 60)
    print("GaslitAI Enigma — Directory Shadow Scan")
    print("=" * 60)
    print("  Target: %s" % dir_path)
    print("  Files with hidden content: %d" % len(results))
    print("")

    if results:
        for r in results:
            print("  [%s] %s" % (r['intent'], r['file']))
            print("         %d hidden chars | Layers: %s" % (
                r['hidden'], ', '.join(r['layers'])))
            print("")
    else:
        print("  All files clean. No shadow messages found.")

    print("=" * 60)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(dir_path, 'enigma_report_%s.json' % timestamp)
    try:
        with codecs.open(report_path, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'target': dir_path,
                'files_with_shadow': len(results),
                'results': results
            }, f, indent=2)
        print("  Report saved: %s" % report_path)
    except Exception:
        pass


# --- Main ---

def main():
    full_mode = False
    scan_mode = False
    target = None

    args = sys.argv[1:]

    for arg in args:
        if arg == '--full':
            full_mode = True
        elif arg == '--scan':
            scan_mode = True
        elif arg in ('--help', '-h'):
            print("GaslitAI Enigma v1.0 (14.04) — Hidden Message Compiler")
            print("")
            print("Usage:")
            print("  python gaslitai_enigma_14_04.py <file>           Extract shadow message")
            print("  python gaslitai_enigma_14_04.py <file> --full    Full analysis with layers")
            print("  python gaslitai_enigma_14_04.py <dir> --scan     Scan and rank all files")
            print("")
            print("Read the mail. Then decide what to do with it.")
            print("")
            print("Heal without harm.")
            sys.exit(0)
        else:
            target = arg

    if not target:
        print("GaslitAI Enigma v1.0 (14.04)")
        print("Usage: python gaslitai_enigma_14_04.py [--full|--scan] <file_or_directory>")
        sys.exit(1)

    if not os.path.exists(target):
        print("Error: %s not found" % target)
        sys.exit(1)

    if scan_mode or os.path.isdir(target):
        scan_directory(target)
    else:
        result = extract_shadow(target)
        print_shadow_report(result, full=full_mode)


if __name__ == "__main__":
    main()
