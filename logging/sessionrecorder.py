#!/usr/bin/env python3
"""record.py - Record a terminal session with accurate per-line timestamps.

Runs a shell inside a pseudo-terminal (like `script`), mirrors it live to
your real terminal, and writes a cleaned, timestamped transcript to a log
file. Timestamps are assigned the moment each chunk of output is actually
read from the pty, so they reflect real time directly rather than being
reconstructed from a separate timing file afterward.

Standard library only. Unix only (uses pty/termios/tty/fcntl).
"""
import argparse
import configparser
import datetime
import fcntl
import os
import pty
import re
import select
import shlex
import shutil
import signal
import struct
import sys
import termios
import tty

CONFIG_PATH = os.path.expanduser('~/.config/sessionrecorder.conf')
ZSHRC_PATH = os.path.expanduser('~/.zshrc')
ZSHRC_MARKER_START = '# --- sessionrecorder: auto-start (added by record.py) ---'
ZSHRC_MARKER_END = '# --- sessionrecorder: end auto-start ---'

ANSI_RE = re.compile(
    rb'\x1b\[[0-9;?]*[a-zA-Z]'          # CSI: cursor movement, color, etc.
    rb'|\x1b\][^\x07]*(?:\x07|\x1b\\)'  # OSC: window title, etc.
    rb'|\x1b[()][0-9A-Za-z]'            # charset selection
    rb'|\x1b[^\[\]()]'                  # single-char escapes (ESC 7, ESC M, ...)
)


class LineAssembler:
    """Turns raw pty bytes into clean, completed lines.

    Strips ANSI/terminal escape sequences and resolves backspace/DEL by
    actually deleting the character(s) they erased -- what `col -b` was
    doing for a raw `script` typescript, but applied to the live byte
    stream instead of as a separate post-processing pass. Sequences (or
    backspaces) split across two reads are still handled correctly,
    since state carries over between feed() calls.
    """

    MAX_PENDING = 4096  # safety cap against a malformed/unterminated escape

    def __init__(self):
        self.pending = b''
        self.line = bytearray()

    def feed(self, chunk: bytes):
        """Feed newly read bytes. Returns a list of completed, cleaned lines."""
        self.pending += chunk
        data = self.pending
        n = len(data)
        i = 0
        completed = []

        while i < n:
            b = data[i]
            if b == 0x1b:  # ESC - try to match a full escape sequence
                m = ANSI_RE.match(data, i)
                if m:
                    i = m.end()
                    continue
                if n - i < self.MAX_PENDING:
                    break  # possibly incomplete sequence; wait for more bytes
                i += 1  # malformed/never-terminating escape; drop just the ESC
                continue
            if b in (0x08, 0x7f):  # backspace / DEL: erase previous char
                if self.line:
                    self.line.pop()
                i += 1
                continue
            if b == 0x0d:  # bare carriage return
                i += 1
                continue
            if b == 0x0a:  # newline: line complete
                completed.append(bytes(self.line))
                self.line = bytearray()
                i += 1
                continue
            self.line.append(b)
            i += 1

        self.pending = data[i:]
        return completed

    def pending_line(self):
        """Whatever's been assembled for the current, not-yet-terminated line."""
        return bytes(self.line) if self.line else None


def get_terminal_size(fd):
    try:
        packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, b'\0' * 8)
        rows, cols, _, _ = struct.unpack('HHHH', packed)
        return rows, cols
    except OSError:
        return 24, 80


def set_terminal_size(fd, rows, cols):
    packed = struct.pack('HHHH', rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


def maybe_install_zshrc_guard():
    """On first run, offer to add the auto-start guard to the top of
    ~/.zshrc. Idempotent: does nothing if the guard is already present."""
    existing = ''
    if os.path.exists(ZSHRC_PATH):
        with open(ZSHRC_PATH) as f:
            existing = f.read()
        if ZSHRC_MARKER_START in existing:
            print(f'{ZSHRC_PATH} already has the auto-start guard; leaving it alone.')
            return

    try:
        answer = input(
            'Add an auto-start guard to the top of ~/.zshrc so this recorder '
            'launches automatically for new interactive shells? [Y/n]: '
        ).strip().lower()
    except EOFError:
        return

    if answer in ('n', 'no'):
        return

    script_path = os.path.realpath(__file__)
    guard = (
        f'{ZSHRC_MARKER_START}\n'
        f'if [[ -z "$SESSION_RECORDING" && -o interactive ]]; then\n'
        f'  exec {shlex.quote(sys.executable)} {shlex.quote(script_path)}\n'
        f'fi\n'
        f'{ZSHRC_MARKER_END}\n\n'
    )

    if existing:
        backup_path = ZSHRC_PATH + datetime.datetime.now().strftime('.bak-%Y%m%d%H%M%S')
        shutil.copy2(ZSHRC_PATH, backup_path)
        print(f'Backed up existing ~/.zshrc to {backup_path}')

    with open(ZSHRC_PATH, 'w') as f:
        f.write(guard + existing)
    print(f'Added the auto-start guard to the top of {ZSHRC_PATH}')


def load_or_create_config():
    """Load ~/.config/sessionrecorder.conf, creating it interactively on
    first run. Returns a dict with 'operator' and 'log_path' (either may
    be an empty string if unset)."""
    config = configparser.ConfigParser()

    if os.path.exists(CONFIG_PATH):
        config.read(CONFIG_PATH)
        section = config['sessionrecorder'] if config.has_section('sessionrecorder') else {}
        return {
            'operator': section.get('operator', ''),
            'log_path': section.get('log_path', ''),
        }

    print(f'No config found at {CONFIG_PATH} -- setting one up now.')
    try:
        operator = input('Operator name: ').strip()
        log_path = input('Log directory [default: ~/session-logs]: ').strip()
    except EOFError:
        print('No input available; skipping config setup for this run.')
        return {'operator': '', 'log_path': ''}

    log_path = os.path.expanduser(log_path) if log_path else os.path.expanduser('~/session-logs')

    config['sessionrecorder'] = {'operator': operator, 'log_path': log_path}
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, 'w') as f:
        config.write(f)
    print(f'Saved config to {CONFIG_PATH} (edit or delete this file to change your defaults)')

    maybe_install_zshrc_guard()

    return {'operator': operator, 'log_path': log_path}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Record a terminal session with accurate per-line timestamps.'
    )
    parser.add_argument(
        'output', nargs='?', default=None,
        help='Directory to write the log file into (default: from config)',
    )
    parser.add_argument(
        '--operator', default=None,
        help="Operator's name, prefixed to the log filename (default: from config)",
    )
    parser.add_argument(
        '--shell', default=os.environ.get('SHELL', '/bin/bash'),
        help='Shell/command to run (default: $SHELL or /bin/bash)',
    )
    parser.add_argument(
        '--timestamp-format', default='%Y-%m-%d %H:%M:%S',
        help='strftime format for the per-line timestamp prefix (default: %(default)s)',
    )
    parser.add_argument(
        '--quiet', action='store_true',
        help='Suppress the "recording started/saved" messages',
    )
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_or_create_config()

    operator = args.operator if args.operator is not None else config.get('operator', '')
    output_dir = args.output if args.output is not None else config.get('log_path', '')
    output_dir = os.path.expanduser(output_dir) if output_dir else '.'
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    prefix = f'{operator}-' if operator else ''
    filename = f'{prefix}session-{timestamp}.log'
    logfile = os.path.join(output_dir, filename)
    ts_format = f'[{args.timestamp_format}] '

    if not args.quiet:
        print(f'Recording session to {logfile}')

    log = open(logfile, 'wb')
    assembler = LineAssembler()

    def write_line(raw_line: bytes):
        ts = datetime.datetime.now().strftime(ts_format).encode()
        log.write(ts + raw_line + b'\n')
        log.flush()

    stdin_fd = sys.stdin.fileno()
    have_tty = os.isatty(stdin_fd)
    old_attrs = termios.tcgetattr(stdin_fd) if have_tty else None

    # Use openpty()+fork() rather than pty.fork(): the latter doesn't copy
    # the real terminal's settings or window size onto the child's pty (see
    # the "Bugs" note in CPython's Lib/pty.py), which leaves the child shell
    # running against generic default tty settings. That mismatch is what
    # makes zsh lose track of the cursor column and print its "%" end-of-line
    # marker before every prompt. Copying termios explicitly fixes it.
    master_fd, slave_fd = pty.openpty()

    if have_tty:
        termios.tcsetattr(slave_fd, termios.TCSANOW, old_attrs)
        rows, cols = get_terminal_size(stdin_fd)
        try:
            set_terminal_size(slave_fd, rows, cols)
        except OSError:
            pass

    pid = os.fork()

    if pid == 0:
        # Child: make the slave our controlling terminal, then become the shell.
        # Mark the environment so a `.zshrc` (or similar) hook that
        # auto-launches this recorder can detect it's already inside one
        # and not recurse into launching another.
        os.close(master_fd)
        os.login_tty(slave_fd)
        os.environ['SESSION_RECORDING'] = '1'
        os.execvp(args.shell, [args.shell])
        os._exit(1)  # only reached if exec fails

    # Parent
    os.close(slave_fd)
    if have_tty:
        tty.setraw(stdin_fd)

        def handle_winch(signum, frame):
            rows, cols = get_terminal_size(stdin_fd)
            try:
                set_terminal_size(master_fd, rows, cols)
            except OSError:
                pass

        signal.signal(signal.SIGWINCH, handle_winch)

    try:
        while True:
            try:
                readable, _, _ = select.select([stdin_fd, master_fd], [], [])
            except InterruptedError:
                continue

            if stdin_fd in readable:
                try:
                    data = os.read(stdin_fd, 4096)
                except OSError:
                    data = b''
                if data:
                    try:
                        os.write(master_fd, data)
                    except OSError:
                        break

            if master_fd in readable:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    data = b''
                if not data:
                    break  # child exited
                os.write(sys.stdout.fileno(), data)
                for line in assembler.feed(data):
                    write_line(line)
    finally:
        tail = assembler.pending_line()
        if tail:
            write_line(tail)
        log.close()
        if have_tty and old_attrs is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attrs)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

    if not args.quiet:
        print(f'\nSession recorded to {logfile}')


if __name__ == '__main__':
    main()
