#!/usr/bin/env python3
"""
sovereign_editor.py
===================

A whitelist-enforcing text editor. The editor accepts only the 98
characters of printable ASCII (U+0020 through U+007E), tab, newline,
and carriage return as direct keyboard input. Pasted content goes
through one of two explicit paths: sanitize-on-paste (Ctrl-V) which
strips every non-whitelist character before insertion, or visualize-
on-paste (Ctrl-B) which inserts the paste verbatim with non-whitelist
characters rendered as visible markers and disables save until the
operator sanitizes.

When opening a file that already contains non-whitelist characters,
the editor renders them inline as [U+XXXX] markers in inverse video
and enters dirty-load mode. Save is disabled in dirty-load mode until
the operator runs the Sanitize action (Ctrl-K) which removes every
non-whitelist character from the buffer.

Key bindings (displayed in the status bar):
  Arrow keys / Home / End / PgUp / PgDn  -- navigate
  Backspace / Delete                     -- delete
  Ctrl-S                                 -- save
  Ctrl-X                                 -- exit
  Ctrl-V                                 -- paste sanitized
  Ctrl-B                                 -- paste verbatim (visualize)
  Ctrl-K                                 -- sanitize entire buffer
  Ctrl-G                                 -- toggle help overlay

No external dependencies. Python 3 standard library only. Clipboard
paste uses xclip, xsel, or wl-paste -- whichever is available.
"""

import curses
import os
import subprocess
import sys


# The whitelist. Same definition as the scanner -- printable ASCII plus
# the three structural whitespace characters tab, LF, CR.
ALLOWED_CODEPOINTS = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def is_allowed(ch):
    """True if `ch` is a single character on the whitelist."""
    return len(ch) == 1 and ord(ch) in ALLOWED_CODEPOINTS


def read_clipboard():
    """
    Read the system clipboard using whichever utility is installed.
    Tries xclip first, then xsel, then wl-paste. Returns the clipboard
    contents as a string, or None if no utility worked.
    """
    candidates = [
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste", "--no-newline"],
    ]
    for cmd in candidates:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            if result.returncode == 0:
                return result.stdout.decode("utf-8", errors="replace")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def sanitize_string(text):
    """Strip every non-whitelist character from `text`."""
    return "".join(ch for ch in text if is_allowed(ch))


def count_contamination(buffer_lines):
    """Count how many non-whitelist characters are in the buffer."""
    total = 0
    for line in buffer_lines:
        for ch in line:
            if not is_allowed(ch):
                total += 1
    return total


class Editor:
    """
    The editor state machine. Holds the buffer, cursor, mode, and the
    methods that mutate them. Curses interaction is kept inside the
    `run` method so the rest of the class is testable without a TTY.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.buffer = [""]
        self.cursor_row = 0
        self.cursor_col = 0
        self.scroll_row = 0
        self.scroll_col = 0
        # dirty: buffer has unsaved changes
        self.dirty = False
        # contamination_locked: buffer contains non-whitelist content
        # that came from a file load or visualize-paste. Save is
        # disabled until the operator runs Sanitize.
        self.contamination_locked = False
        self.status_message = ""
        self.show_help = False
        self.load()

    def load(self):
        """Load the file if it exists. Empty buffer otherwise."""
        if self.file_path and os.path.isfile(self.file_path):
            with open(self.file_path, "r", encoding="utf-8",
                      errors="replace") as fh:
                content = fh.read()
            self.buffer = content.split("\n")
            if not self.buffer:
                self.buffer = [""]
            if count_contamination(self.buffer) > 0:
                self.contamination_locked = True
                self.status_message = ("Loaded file contains non-whitelist "
                                       "characters. Save disabled. "
                                       "Ctrl-K to sanitize.")
        else:
            self.buffer = [""]
            self.status_message = f"New file: {self.file_path}"

    def save(self):
        """Save buffer to file, refusing if contamination_locked."""
        if self.contamination_locked:
            self.status_message = ("Save blocked: buffer contains "
                                   "non-whitelist content. Ctrl-K to sanitize.")
            return False
        with open(self.file_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self.buffer))
        self.dirty = False
        self.status_message = f"Saved {self.file_path}"
        return True

    def sanitize_buffer(self):
        """Remove every non-whitelist character from the buffer."""
        removed = 0
        for i, line in enumerate(self.buffer):
            clean = sanitize_string(line)
            removed += len(line) - len(clean)
            self.buffer[i] = clean
        # Clamp cursor in case sanitization shortened the current line.
        self.cursor_col = min(self.cursor_col, len(self.buffer[self.cursor_row]))
        self.contamination_locked = False
        self.dirty = True
        self.status_message = f"Sanitized: removed {removed} non-whitelist characters"

    def insert_char(self, ch):
        """Insert a single character at the cursor if whitelist allows."""
        if not is_allowed(ch):
            self.status_message = f"Blocked: U+{ord(ch):04X} not on whitelist"
            return
        if ch == "\n":
            # Split current line at cursor.
            current = self.buffer[self.cursor_row]
            before = current[:self.cursor_col]
            after = current[self.cursor_col:]
            self.buffer[self.cursor_row] = before
            self.buffer.insert(self.cursor_row + 1, after)
            self.cursor_row += 1
            self.cursor_col = 0
        else:
            line = self.buffer[self.cursor_row]
            self.buffer[self.cursor_row] = (
                line[:self.cursor_col] + ch + line[self.cursor_col:])
            self.cursor_col += 1
        self.dirty = True

    def insert_string(self, text, sanitize):
        """
        Insert a string at the cursor. If `sanitize` is True, every
        non-whitelist character is dropped. If False, the string is
        inserted verbatim and the editor enters contamination-locked
        mode if any non-whitelist character was inserted.
        """
        if sanitize:
            cleaned = sanitize_string(text)
            for ch in cleaned:
                if ch == "\n":
                    self.insert_char("\n")
                else:
                    self.insert_char(ch)
            self.status_message = (f"Pasted {len(cleaned)} chars "
                                   f"(stripped {len(text) - len(cleaned)})")
        else:
            for ch in text:
                if ch == "\n":
                    # Even in visualize mode, newlines split lines so the
                    # buffer structure stays sane.
                    current = self.buffer[self.cursor_row]
                    before = current[:self.cursor_col]
                    after = current[self.cursor_col:]
                    self.buffer[self.cursor_row] = before
                    self.buffer.insert(self.cursor_row + 1, after)
                    self.cursor_row += 1
                    self.cursor_col = 0
                else:
                    line = self.buffer[self.cursor_row]
                    self.buffer[self.cursor_row] = (
                        line[:self.cursor_col] + ch + line[self.cursor_col:])
                    self.cursor_col += 1
            self.dirty = True
            if count_contamination(self.buffer) > 0:
                self.contamination_locked = True
                self.status_message = ("Pasted verbatim. Buffer contains "
                                       "non-whitelist content. Save disabled.")
            else:
                self.status_message = f"Pasted {len(text)} chars (clean)"

    def backspace(self):
        if self.cursor_col > 0:
            line = self.buffer[self.cursor_row]
            self.buffer[self.cursor_row] = (
                line[:self.cursor_col - 1] + line[self.cursor_col:])
            self.cursor_col -= 1
            self.dirty = True
        elif self.cursor_row > 0:
            # Join with previous line.
            prev_len = len(self.buffer[self.cursor_row - 1])
            self.buffer[self.cursor_row - 1] += self.buffer[self.cursor_row]
            del self.buffer[self.cursor_row]
            self.cursor_row -= 1
            self.cursor_col = prev_len
            self.dirty = True

    def delete(self):
        line = self.buffer[self.cursor_row]
        if self.cursor_col < len(line):
            self.buffer[self.cursor_row] = (
                line[:self.cursor_col] + line[self.cursor_col + 1:])
            self.dirty = True
        elif self.cursor_row < len(self.buffer) - 1:
            self.buffer[self.cursor_row] += self.buffer[self.cursor_row + 1]
            del self.buffer[self.cursor_row + 1]
            self.dirty = True

    def move_cursor(self, dy, dx):
        new_row = max(0, min(len(self.buffer) - 1, self.cursor_row + dy))
        self.cursor_row = new_row
        self.cursor_col = max(0, min(len(self.buffer[self.cursor_row]),
                                     self.cursor_col + dx))

    def render_line(self, line):
        """
        Return a list of (segment, is_marker) tuples for display. Each
        segment is either a run of allowed characters or a single
        non-whitelist character rendered as [U+XXXX]. The caller uses
        the is_marker flag to apply inverse video for the markers.
        """
        segments = []
        run = []
        for ch in line:
            if is_allowed(ch):
                run.append(ch)
            else:
                if run:
                    segments.append(("".join(run), False))
                    run = []
                segments.append((f"[U+{ord(ch):04X}]", True))
        if run:
            segments.append(("".join(run), False))
        return segments

    def display_column(self, line, logical_col):
        """
        Convert a logical column (character index) to a display column
        (terminal cell index) by expanding markers. Cursor positioning
        on the screen uses this so the cursor lands on the right cell
        even when markers are wider than one cell.
        """
        col = 0
        for i, ch in enumerate(line):
            if i >= logical_col:
                break
            if is_allowed(ch):
                col += 1
            else:
                # The marker [U+XXXX] is 8 cells wide.
                col += 8
        return col

    def run(self, stdscr):
        """The curses event loop. Owns all screen interaction."""
        curses.curs_set(1)
        stdscr.keypad(True)
        # Color setup. Pair 1 is normal text; pair 2 is contamination
        # markers; pair 3 is the status bar; pair 4 is warnings.
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE, -1)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_RED)
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_RED)

        while True:
            self.draw(stdscr)
            try:
                key = stdscr.get_wch()
            except curses.error:
                continue
            if isinstance(key, str):
                cp = ord(key)
                # Ctrl-X (0x18) -- exit
                if cp == 0x18:
                    if self.dirty and not self.contamination_locked:
                        self.status_message = ("Unsaved changes. "
                                               "Ctrl-S to save or Ctrl-X again to exit.")
                        self.dirty = False  # Confirms on second press.
                        continue
                    break
                # Ctrl-S (0x13) -- save
                elif cp == 0x13:
                    self.save()
                # Ctrl-V (0x16) -- paste sanitized
                elif cp == 0x16:
                    clip = read_clipboard()
                    if clip is None:
                        self.status_message = "No clipboard utility (xclip/xsel/wl-paste)"
                    else:
                        self.insert_string(clip, sanitize=True)
                # Ctrl-B (0x02) -- paste verbatim with visualization
                elif cp == 0x02:
                    clip = read_clipboard()
                    if clip is None:
                        self.status_message = "No clipboard utility (xclip/xsel/wl-paste)"
                    else:
                        self.insert_string(clip, sanitize=False)
                # Ctrl-K (0x0B) -- sanitize buffer
                elif cp == 0x0B:
                    self.sanitize_buffer()
                # Ctrl-G (0x07) -- toggle help
                elif cp == 0x07:
                    self.show_help = not self.show_help
                # Enter
                elif cp == 0x0A or cp == 0x0D:
                    self.insert_char("\n")
                # Tab
                elif cp == 0x09:
                    self.insert_char("\t")
                # Backspace (0x7F or 0x08 depending on terminal)
                elif cp == 0x7F or cp == 0x08:
                    self.backspace()
                # Other printable
                elif 0x20 <= cp <= 0x7E:
                    self.insert_char(key)
                else:
                    # Non-whitelist keyboard input is silently refused
                    # with a status message. This is the editor's
                    # primary defense -- no path for non-ASCII to enter
                    # the buffer except through an explicit paste mode.
                    self.status_message = f"Blocked: U+{cp:04X} not on whitelist"
            else:
                # Special key codes from curses (arrows, function keys, etc.)
                if key == curses.KEY_LEFT:
                    self.move_cursor(0, -1)
                elif key == curses.KEY_RIGHT:
                    self.move_cursor(0, 1)
                elif key == curses.KEY_UP:
                    self.move_cursor(-1, 0)
                elif key == curses.KEY_DOWN:
                    self.move_cursor(1, 0)
                elif key == curses.KEY_HOME:
                    self.cursor_col = 0
                elif key == curses.KEY_END:
                    self.cursor_col = len(self.buffer[self.cursor_row])
                elif key == curses.KEY_PPAGE:
                    rows = stdscr.getmaxyx()[0] - 3
                    self.move_cursor(-rows, 0)
                elif key == curses.KEY_NPAGE:
                    rows = stdscr.getmaxyx()[0] - 3
                    self.move_cursor(rows, 0)
                elif key == curses.KEY_BACKSPACE:
                    self.backspace()
                elif key == curses.KEY_DC:
                    self.delete()
                elif key == curses.KEY_RESIZE:
                    pass  # Will redraw on next loop.

    def draw(self, stdscr):
        """Render the buffer, status bar, and help overlay."""
        stdscr.erase()
        rows, cols = stdscr.getmaxyx()
        buf_rows = rows - 2  # Reserve two lines for status and hints.

        # Adjust scrolling so the cursor is visible.
        if self.cursor_row < self.scroll_row:
            self.scroll_row = self.cursor_row
        elif self.cursor_row >= self.scroll_row + buf_rows:
            self.scroll_row = self.cursor_row - buf_rows + 1

        # Render visible lines.
        for screen_y in range(buf_rows):
            buf_y = self.scroll_row + screen_y
            if buf_y >= len(self.buffer):
                break
            x = 0
            for segment, is_marker in self.render_line(self.buffer[buf_y]):
                if x >= cols:
                    break
                attr = curses.color_pair(2) | curses.A_REVERSE if is_marker \
                    else curses.color_pair(1)
                try:
                    stdscr.addstr(screen_y, x, segment[:cols - x], attr)
                except curses.error:
                    pass
                x += len(segment)

        # Status bar.
        contamination = count_contamination(self.buffer)
        status_left = (f" {self.file_path or '[no file]'} "
                       f"{'[modified] ' if self.dirty else ''}"
                       f"{'[LOCKED] ' if self.contamination_locked else ''}"
                       f"contamination={contamination} "
                       f"line {self.cursor_row + 1} col {self.cursor_col + 1}")
        status_right = self.status_message
        status_line = status_left + " " * max(0, cols - len(status_left)
                                              - len(status_right) - 1) \
                                  + status_right
        try:
            stdscr.addstr(rows - 2, 0, status_line[:cols - 1],
                          curses.color_pair(3))
        except curses.error:
            pass

        # Key hints bar.
        if self.show_help:
            hints = ("^S save  ^X exit  ^V paste-clean  ^B paste-visual  "
                     "^K sanitize  ^G hide-help")
        else:
            hints = ("^S save  ^X exit  ^V paste-clean  ^B paste-visual  "
                     "^K sanitize  ^G help")
        try:
            stdscr.addstr(rows - 1, 0, hints[:cols - 1])
        except curses.error:
            pass

        # Cursor placement.
        line = self.buffer[self.cursor_row]
        screen_y = self.cursor_row - self.scroll_row
        screen_x = self.display_column(line, self.cursor_col)
        if 0 <= screen_y < buf_rows and 0 <= screen_x < cols:
            try:
                stdscr.move(screen_y, screen_x)
            except curses.error:
                pass

        stdscr.refresh()


def main():
    if len(sys.argv) < 2:
        print("Usage: sovereign_editor.py <file>", file=sys.stderr)
        sys.exit(2)
    editor = Editor(sys.argv[1])
    curses.wrapper(editor.run)


if __name__ == "__main__":
    main()
