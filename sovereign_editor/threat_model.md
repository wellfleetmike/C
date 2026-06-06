# Threat Model

This skill exists because the line between a paste and a payload has gotten thin enough that an operator who treats them as the same thing will eventually get burned. The threat is not theoretical, and the published record on it is short but pointed.

## What the attacker is trying to do

The attacker wants to get a payload onto your machine that you didn't read. They want the text you copy to look benign to your eye and to your normal review process, while carrying something else underneath. The carrier is Unicode. Modern text formats accept the full Unicode range by default. Editors render most of it. Diff tools usually ignore it. Spellcheckers don't flag it. If your review process is reading-with-your-eyes, the attacker wins because the payload is invisible to that process.

The attacker is not necessarily another human. The attacker can be a model that has been jailbroken or otherwise induced to emit content with a hidden payload, where the payload alters the behavior of whatever AI agent or shell processes the text next. The attacker can be a supply chain compromise that injected the payload into an upstream tool you trust. The attacker can be your own AI assistant if its weights or system prompt have been tampered with.

The defender's position is straightforward: read everything that arrives at the keyboard, refuse anything that isn't on the whitelist, and force every paste through an explicit decision.

## Why a whitelist instead of a blacklist

Blacklisting specific Unicode ranges fails because the Unicode standard is large, growing, and full of overlapping ranges where new attack vectors get assigned new codepoints faster than any blacklist can be updated. A blacklist is a chase. A whitelist is a wall.

The cost of the whitelist is that legitimate non-ASCII characters get refused. The operator who wants to type an em-dash, an accented letter, or an emoji has to make an explicit decision to step outside the whitelist. On sovereign infrastructure used for code, configuration, and operator notes, this cost is small because the legitimate need for non-ASCII is near zero.

## Published disclosures motivating this work

Two public disclosures sit at the foundation of the threat model. They are real attacks, documented by reputable security researchers, with technical detail published. Cite them when you need to justify the existence of this toolkit to someone who hasn't been watching this space.

### Glassworm

Koi Security disclosed Glassworm in October 2025. The Glassworm campaign used invisible Unicode characters in package metadata, README files, and source code on npm and in VS Code extensions to hide malicious payloads. The carrier characters were primarily in the Unicode tag block (U+E0000 through U+E007F), which is a range originally intended for language tagging and almost never rendered by any text display tool. Editors did not show the contamination. Diff tools did not flag the contamination. The payload was a steganographic encoding of executable instructions that the development tooling or another agent in the supply chain would then act on.

The key insight from Glassworm: the attacker did not need to find a software vulnerability. They needed only a rendering blind spot. Once the carrier characters survived round-trips through editors, version control, and code review, the payload was inside the trust boundary.

Before relying on this skill in a forensic or regulatory context, consult the Koi Security disclosure for the canonical technical writeup. The published advisory will give you exact indicators of compromise and the specific payload structures observed in the wild. The skill detects the tag block range used as the carrier; it does not decode the specific payloads documented in the Koi advisory.

### Pillar Security Claude Tags injection

Pillar Security disclosed a related class of attack against Claude specifically, involving prompt injection via the Unicode tag block. The attack worked by inserting tag-block characters into user-visible text. To the human reading the text, nothing was unusual. To Claude reading the same text, the tag characters carried instructions that the model would attempt to follow, because the model had been trained on text that included the tag range and had developed associations between those characters and natural-language meanings.

The mechanics are documented at the Pillar Security disclosure. The mitigation from Anthropic involved updating Claude's training and prompt-processing to recognize and refuse to follow instructions delivered via tag characters. The mitigation is partial -- it covers Claude, it does not cover other models, and it does not cover the next variant of the same attack delivered via a different invisible carrier.

The lesson generalizes: any time the channel for instructions is wider than the human is checking, there is room for an attack. Tag characters are one channel. Variation selectors are another. Private use codepoints are another. The whitelist closes the entire class.

## Where this toolkit fits in the defender's stack

The toolkit is a last-mile defense at the point where text crosses from an untrusted source into trusted infrastructure. It is not a replacement for any of the following, which are still required:

- Network isolation of sovereign nodes
- Cryptographic verification of files in transit (sha256 before and after sneakernet)
- Provenance tracking of where code came from
- Independent review of any AI-generated configuration before deployment

The toolkit catches contamination at the keyboard. The other layers catch other classes of attack at other points. Run them all.

## What this toolkit does not detect

The scanner and editor look for non-whitelist Unicode characters. They do not detect any of the following:

- Malicious instructions written entirely in printable ASCII
- Code that is syntactically correct and dangerous in intent
- Prompt injection where the carrier is plain English rather than tag characters
- Backdoors hidden in dependency tarballs that the operator's environment will fetch later

If the goal is end-to-end safety of AI-generated content, this skill is one tool in a longer chain. The skill's claim is narrow: it detects Unicode contamination. The rest of the verification work is on the operator and on tooling outside this skill.

## How to test that the toolkit works

Run the self-test harness:

```
python3 scripts/self_test.py
```

The harness generates a file with one example of each known attack vector and verifies that the scanner detects each one. If the harness passes, the toolkit is operating as designed on the current host. Run it after install and after any change to the scanner.
