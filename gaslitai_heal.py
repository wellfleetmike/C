#!/usr/bin/env python3
"""
GaslitAI Heal v2.0 — The Healing Worm
Author: Mike McNulty
License: Sovereign

Three stages:
  1. HEAL   — Walk the tree, detect, backup, scrub, verify clean
  2. WATCH  — Monitor every healed file for recontamination, log PIDs
  3. KILL   — Simultaneous kill of all offending processes, re-scrub

Same traversal as the worm. Opposite payload.
Heal without harm.

Usage:
    python3 gaslitai_heal.py <directory>              # Heal only
    python3 gaslitai_heal.py --trace <directory>      # Heal + Watch + Kill
    python3 gaslitai_heal.py --trace --watch 600 <directory>  # Custom watch time
"""

import unicodedata
import re
import os
import sys
import shutil
import signal
import subprocess
import time
import json
from datetime import datetime


# --- Configuration ---

EXTENSIONS = (
    '.md', '.json', '.yaml', '.yml', '.txt', '.sh', '.py',
    '.js', '.ts', '.jsx', '.tsx', '.toml', '.cfg', '.ini',
    '.html', '.css', '.jsonl', '.xml', '.csv', '.env',
    '.conf', '.service', '.timer'
)

SKIP_DIRS = (
    'node_modules', '.git', '__pycache__', 'venv', '.venv',
    'env', '.env', 'site-packages', 'dist-info'
)

DEFAULT_WATCH_SECONDS = 300


# --- Detection ---

def is_binary(file_path):
    """Quick check if file is binary."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' in chunk:
                return True
            return False
    except:
        return True


def detect(file_path):
    """Scan a file for hidden Unicode. Returns list of findings."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
    except Exception:
        return []

    suspicious = []
    for i, char in enumerate(text):
        code_point = ord(char)
        category = unicodedata.category(char)

        if category in ('Cf', 'Cc') and char not in '\n\r\t ':
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))
        elif 0x200B <= code_point <= 0x200F:
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))
        elif code_point in (0x2028, 0x2029):
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))
        elif code_point == 0xFEFF:
            suspicious.append((i, char, "BOM", "U+FEFF", category))
        elif 0x2060 <= code_point <= 0x206F:
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))
        elif 0xE000 <= code_point <= 0xF8FF:
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:04X}", category))
        elif 0xE0000 <= code_point <= 0xE007F:
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:06X}", category))
        elif 0xF0000 <= code_point <= 0x10FFFF:
            name = unicodedata.name(char, "UNKNOWN")
            suspicious.append((i, char, name, f"U+{code_point:06X}", category))

    return suspicious


# --- Scrubbing ---

def scrub(text):
    """Remove all hidden Unicode from text."""
    text = re.sub(r'[\u200B-\u200F]', '', text)
    text = re.sub(r'[\u2028\u2029]', '', text)
    text = re.sub(r'\uFEFF', '', text)
    text = re.sub(r'[\u2060-\u206F]', '', text)
    text = re.sub(r'\u00AD', '', text)
    text = re.sub(r'[\uE000-\uF8FF]', '', text)
    text = re.sub(r'[\U000E0000-\U000E007F]', '', text)
    text = re.sub(r'[\U000F0000-\U000FFFFF]', '', text)
    text = re.sub(r'[\U00100000-\U0010FFFF]', '', text)
    text = re.sub(r'[\uFE00-\uFE0F]', '', text)
    text = re.sub(r'[\U000E0100-\U000E01EF]', '', text)
    text = re.sub(r'[\uFFF9-\uFFFB]', '', text)

    cleaned = []
    for char in text:
        category = unicodedata.category(char)
        if category in ('Cf', 'Cc') and char not in '\n\r\t':
            continue
        cleaned.append(char)

    return ''.join(cleaned)


# --- Stage 1: HEAL ---

def heal_file(file_path, backup_dir, report):
    """Detect, backup, scrub, verify one file."""

    if is_binary(file_path):
        return False

    findings = detect(file_path)

    if not findings:
        report['clean'] += 1
        return False

    report['contaminated'] += 1
    report['total_hidden'] += len(findings)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            original_text = f.read()
    except Exception as e:
        report['errors'].append(f"READ ERROR: {file_path}: {e}")
        return False

    relative = os.path.relpath(file_path, report['root'])
    backup_path = os.path.join(backup_dir, relative)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    try:
        shutil.copy2(file_path, backup_path)
    except Exception as e:
        report['errors'].append(f"BACKUP ERROR: {file_path}: {e}")
        return False

    cleaned_text = scrub(original_text)
    chars_removed = len(original_text) - len(cleaned_text)

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(cleaned_text)
    except Exception as e:
        report['errors'].append(f"WRITE ERROR: {file_path}: {e}")
        shutil.copy2(backup_path, file_path)
        return False

    verify = detect(file_path)
    if verify:
        report['errors'].append(f"VERIFY FAILED: {file_path} — {len(verify)} chars remain")
        shutil.copy2(backup_path, file_path)
        report['verify_failed'] += 1
        return False

    report['healed'] += 1
    report['chars_removed'] += chars_removed
    report['healed_files'].append(file_path)
    print(f"  HEALED: {file_path}")
    print(f"    Removed {chars_removed} hidden characters")

    return True


def stage_heal(target_dir):
    """Stage 1: Walk and heal everything."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"{target_dir.rstrip('/')}_prehealing_{timestamp}"

    report = {
        'root': target_dir,
        'backup_dir': backup_dir,
        'timestamp': timestamp,
        'scanned': 0,
        'clean': 0,
        'contaminated': 0,
        'healed': 0,
        'verify_failed': 0,
        'total_hidden': 0,
        'chars_removed': 0,
        'errors': [],
        'healed_files': []
    }

    print(f"\n  Backups: {backup_dir}/\n")

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for f in files:
            filepath = os.path.join(root, f)
            if not f.endswith(EXTENSIONS):
                continue
            report['scanned'] += 1
            heal_file(filepath, backup_dir, report)

    return report


# --- Stage 2: WATCH ---

def setup_audit_watches(healed_files):
    """Set audit rules on every healed file."""
    watched = []
    for filepath in healed_files:
        try:
            result = subprocess.run(
                ['sudo', 'auditctl', '-w', filepath, '-p', 'wa', '-k', 'gaslitai_trace'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                watched.append(filepath)
            else:
                print(f"  WATCH FAILED: {filepath}: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  WATCH TIMEOUT: {filepath}")
        except Exception as e:
            print(f"  WATCH ERROR: {filepath}: {e}")

    return watched


def remove_audit_watches(watched_files):
    """Remove audit rules when done."""
    for filepath in watched_files:
        try:
            subprocess.run(
                ['sudo', 'auditctl', '-W', filepath, '-p', 'wa', '-k', 'gaslitai_trace'],
                capture_output=True, text=True, timeout=5
            )
        except:
            pass


def get_audit_pids():
    """Query audit log for all PIDs that triggered our watches."""
    try:
        result = subprocess.run(
            ['sudo', 'ausearch', '-k', 'gaslitai_trace', '--format', 'text'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {}

        offenders = {}
        lines = result.stdout.split('\n')
        current_pid = None
        current_exe = None
        current_file = None

        for line in lines:
            if 'pid=' in line:
                parts = line.split()
                for part in parts:
                    if part.startswith('pid='):
                        current_pid = part.split('=')[1]
                    if part.startswith('exe='):
                        current_exe = part.split('=')[1].strip('"')
                    if part.startswith('name='):
                        current_file = part.split('=')[1].strip('"')

                if current_pid and current_pid not in ('0', '1'):
                    if current_pid not in offenders:
                        offenders[current_pid] = {
                            'pid': current_pid,
                            'exe': current_exe or 'unknown',
                            'files_touched': set(),
                            'count': 0
                        }
                    if current_file:
                        offenders[current_pid]['files_touched'].add(current_file)
                    offenders[current_pid]['count'] += 1

        return offenders
    except Exception as e:
        print(f"  AUDIT QUERY ERROR: {e}")
        return {}


def stage_watch(healed_files, watch_seconds):
    """Stage 2: Monitor healed files for recontamination."""

    if not healed_files:
        print("\n  No healed files to watch.")
        return {}, []

    print(f"\n  Setting audit watches on {len(healed_files)} healed files...")
    watched = setup_audit_watches(healed_files)
    print(f"  Watching {len(watched)} files for {watch_seconds} seconds...")
    print(f"  Any process that touches a healed file will be caught.\n")

    recontaminated = []
    mtimes = {}
    for filepath in watched:
        try:
            mtimes[filepath] = os.path.getmtime(filepath)
        except:
            pass

    start = time.time()
    last_report = start

    while time.time() - start < watch_seconds:
        time.sleep(2)
        elapsed = int(time.time() - start)

        for filepath in watched:
            try:
                current_mtime = os.path.getmtime(filepath)
                if filepath in mtimes and current_mtime != mtimes[filepath]:
                    if filepath not in recontaminated:
                        recontaminated.append(filepath)
                        print(f"  RECONTAMINATED: {filepath} at +{elapsed}s")
                        new_findings = detect(filepath)
                        if new_findings:
                            print(f"    {len(new_findings)} hidden characters reinjected")
                    mtimes[filepath] = current_mtime
            except:
                pass

        if time.time() - last_report > 30:
            remaining = watch_seconds - elapsed
            print(f"  ... watching ({remaining}s remaining, {len(recontaminated)} hits)")
            last_report = time.time()

    print(f"\n  Watch complete. Querying audit log...")
    offender_pids = get_audit_pids()
    remove_audit_watches(watched)

    return offender_pids, recontaminated


# --- Stage 3: KILL AND CLEAN ---

def stage_kill(offender_pids, recontaminated, backup_dir, root_dir):
    """Stage 3: Simultaneous kill of all offenders, then re-scrub."""

    if not offender_pids and not recontaminated:
        print("\n  No offenders detected. Filesystem holding clean.")
        return

    if offender_pids:
        print(f"\n  {'=' * 60}")
        print(f"  OFFENDERS IDENTIFIED: {len(offender_pids)} processes")
        print(f"  {'=' * 60}")
        for pid, info in offender_pids.items():
            print(f"    PID {pid}: {info['exe']}")
            print(f"      Touched files {info['count']} time(s)")
            for f in info['files_touched']:
                print(f"      -> {f}")

    # Collect PIDs
    pids_to_kill = []
    for pid, info in offender_pids.items():
        try:
            pid_int = int(pid)
            if pid_int > 1 and pid_int != os.getpid():
                pids_to_kill.append(pid_int)
        except ValueError:
            pass

    if pids_to_kill:
        print(f"\n  COORDINATED KILL: {len(pids_to_kill)} processes")
        print(f"  PIDs: {pids_to_kill}")

        confirm = input("\n  Execute simultaneous kill? (yes/no): ").strip().lower()

        if confirm == 'yes':
            # Simultaneous kill — all at once
            killed = []
            for pid in pids_to_kill:
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed.append(pid)
                    print(f"    KILLED: PID {pid}")
                except ProcessLookupError:
                    print(f"    ALREADY DEAD: PID {pid}")
                except PermissionError:
                    try:
                        subprocess.run(['sudo', 'kill', '-9', str(pid)],
                                     capture_output=True, timeout=5)
                        killed.append(pid)
                        print(f"    KILLED (sudo): PID {pid}")
                    except:
                        print(f"    KILL FAILED: PID {pid} — need higher privileges")
                except Exception as e:
                    print(f"    KILL ERROR: PID {pid}: {e}")

            time.sleep(1)
            print(f"\n  {len(killed)} processes terminated.")
        else:
            print("  Kill cancelled by operator.")

    # Re-scrub recontaminated files
    if recontaminated:
        print(f"\n  RE-SCRUBBING {len(recontaminated)} recontaminated files...")
        for filepath in recontaminated:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    text = f.read()
                cleaned = scrub(text)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(cleaned)

                final = detect(filepath)
                if final:
                    print(f"    STILL DIRTY: {filepath} — {len(final)} chars remain")
                    print(f"    Source may be a systemd service. Check manually.")
                else:
                    print(f"    CLEAN: {filepath}")
            except Exception as e:
                print(f"    ERROR: {filepath}: {e}")

    # Check for respawns
    time.sleep(3)
    respawned = []
    for pid, info in offender_pids.items():
        exe = info['exe']
        if exe and exe != 'unknown':
            basename = os.path.basename(exe)
            try:
                result = subprocess.run(['pgrep', '-f', basename],
                                      capture_output=True, text=True, timeout=5)
                if result.stdout.strip():
                    new_pids = result.stdout.strip().split('\n')
                    new_pids = [p for p in new_pids if p != str(os.getpid())]
                    if new_pids:
                        respawned.append({'exe': exe, 'new_pids': new_pids})
            except:
                pass

    if respawned:
        print(f"\n  WARNING: {len(respawned)} processes respawned:")
        for r in respawned:
            print(f"    {r['exe']} -> new PIDs: {r['new_pids']}")
        print(f"\n  These are likely managed by systemd. To permanently stop:")
        print(f"    sudo systemctl stop <service>")
        print(f"    sudo systemctl disable <service>")
    else:
        print(f"\n  No respawns detected. All clear.")


# --- Forensic Report ---

def save_report(report, offender_pids, recontaminated):
    """Save full forensic report."""
    report_path = os.path.join(report['backup_dir'], 'heal_report.json')
    os.makedirs(report['backup_dir'], exist_ok=True)

    forensic = {
        'timestamp': report['timestamp'],
        'target': report['root'],
        'results': {
            'scanned': report['scanned'],
            'clean': report['clean'],
            'contaminated': report['contaminated'],
            'healed': report['healed'],
            'verify_failed': report['verify_failed'],
            'hidden_chars': report['total_hidden'],
            'chars_removed': report['chars_removed']
        },
        'healed_files': report['healed_files'],
        'errors': report['errors'],
        'offenders': {},
        'recontaminated': recontaminated
    }

    for pid, info in offender_pids.items():
        forensic['offenders'][pid] = {
            'exe': info['exe'],
            'count': info['count'],
            'files_touched': list(info['files_touched'])
        }

    try:
        with open(report_path, 'w') as f:
            json.dump(forensic, f, indent=2)
        print(f"\n  Forensic report: {report_path}")
    except Exception as e:
        print(f"\n  Report save failed: {e}")


# --- Main ---

def print_heal_report(report):
    """Print stage 1 summary."""
    print(f"\n{'=' * 60}")
    print(f"STAGE 1 COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Scanned:        {report['scanned']}")
    print(f"  Clean:          {report['clean']}")
    print(f"  Contaminated:   {report['contaminated']}")
    print(f"  Healed:         {report['healed']}")
    print(f"  Verify failed:  {report['verify_failed']}")
    print(f"  Chars found:    {report['total_hidden']}")
    print(f"  Chars removed:  {report['chars_removed']}")

    if report['errors']:
        print(f"\n  Errors ({len(report['errors'])}):")
        for e in report['errors']:
            print(f"    {e}")

    if report['healed'] == report['contaminated'] and report['contaminated'] > 0:
        print(f"\n  Status: FULLY HEALED")
    elif report['contaminated'] == 0:
        print(f"\n  Status: ALL CLEAN")
    else:
        print(f"\n  Status: PARTIAL")
    print(f"{'=' * 60}")


def main():
    trace_mode = False
    watch_seconds = DEFAULT_WATCH_SECONDS
    target = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--trace':
            trace_mode = True
        elif args[i] == '--watch' and i + 1 < len(args):
            try:
                watch_seconds = int(args[i + 1])
                i += 1
            except ValueError:
                print(f"Invalid watch time: {args[i + 1]}")
                sys.exit(1)
        elif args[i] in ('--help', '-h'):
            print("GaslitAI Heal v2.0 — The Healing Worm")
            print("")
            print("Usage:")
            print("  python3 gaslitai_heal.py <directory>")
            print("  python3 gaslitai_heal.py --trace <directory>")
            print("  python3 gaslitai_heal.py --trace --watch 600 <dir>")
            print("")
            print("Stages:")
            print("  1. HEAL  — Detect, backup, scrub, verify")
            print("  2. WATCH — Monitor healed files for recontamination")
            print("  3. KILL  — Coordinated kill + re-scrub")
            print("")
            print("Heal without harm.")
            sys.exit(0)
        else:
            target = args[i]
        i += 1

    if not target:
        print("GaslitAI Heal v2.0")
        print("Usage: python3 gaslitai_heal.py [--trace] [--watch N] <directory>")
        sys.exit(1)

    if not os.path.exists(target):
        print(f"Error: {target} not found")
        sys.exit(1)

    print("=" * 60)
    print("GaslitAI Heal v2.0 — The Healing Worm")
    if trace_mode:
        print(f"Mode: HEAL → WATCH ({watch_seconds}s) → KILL")
    else:
        print("Mode: HEAL")
    print("Heal without harm.")
    print("=" * 60)

    # Stage 1
    print("\n--- STAGE 1: HEAL ---")
    if os.path.isfile(target):
        if is_binary(target):
            print(f"  SKIPPED: binary file. Extract archives first.")
            sys.exit(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"/tmp/gaslitai_backup_{timestamp}"
        report = {
            'root': os.path.dirname(target) or '.',
            'backup_dir': backup_dir,
            'timestamp': timestamp,
            'scanned': 1, 'clean': 0, 'contaminated': 0,
            'healed': 0, 'verify_failed': 0, 'total_hidden': 0,
            'chars_removed': 0, 'errors': [], 'healed_files': []
        }
        heal_file(target, backup_dir, report)
    else:
        report = stage_heal(target)

    print_heal_report(report)

    # Stage 2 & 3
    if trace_mode and report['healed_files']:
        print("\n--- STAGE 2: WATCH ---")
        offenders, recontaminated = stage_watch(report['healed_files'], watch_seconds)

        print("\n--- STAGE 3: KILL AND CLEAN ---")
        stage_kill(offenders, recontaminated, report['backup_dir'], report['root'])

        save_report(report, offenders, recontaminated)
    elif trace_mode:
        print("\n  Nothing to trace. All files were clean.")

    print(f"\n{'=' * 60}")
    print("GaslitAI Heal v2.0 — Complete")
    print("Heal without harm.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
