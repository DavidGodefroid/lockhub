#!/usr/bin/env python3
"""Drives an interactive command at a pseudo-terminal, as a human would.

    expect.py TIMEOUT [PATTERN ANSWER]... -- CMD...

CMD runs at a pseudo-terminal (lox init: its questions, lox up's review,
and the consoles it attaches to). The rules apply in order: once PATTERN
is seen in the output (after where the previous rule matched), ANSWER is
typed. An ANSWER starting with <pause> waits 3 seconds first (a console
attached does not replay its pending question: what is typed before the
attach is connected is lost); <detach> types Ctrl-P Ctrl-Q (detaches
from a console). A PATTERN starting with <opt> is optional: it is
skipped once the next rule's pattern shows first (lox run's review, asked
only when the configuration changed). Answers take \\n escapes. Once
every rule matched, the command's exit status is ours. Exit 1 when a pattern is not seen within
TIMEOUT seconds (the pattern is named; answers are never printed). The
output is copied to stdout.
"""
import os
import pty
import select
import sys
import time


def main():
    args = sys.argv[1:]
    cut = args.index("--")
    head, cmd = args[:cut], args[cut + 1:]
    timeout = float(head[0])
    rules = [(head[i], head[i + 1]) for i in range(1, len(head), 2)]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    out = ""
    pos = 0
    deadline = time.time() + timeout
    eof = False
    while time.time() < deadline and not eof:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                b = os.read(fd, 4096)
            except OSError:
                b = b""
            if not b:
                eof = True
            else:
                s = b.decode(errors="replace")
                sys.stdout.write(s)
                sys.stdout.flush()
                out += s
        while rules:
            pat, ans = rules[0]
            opt = pat.startswith("<opt>")
            if opt:
                pat = pat[len("<opt>"):]
            j = out.find(pat, pos)
            if j < 0 and opt and len(rules) > 1 and out.find(rules[1][0], pos) >= 0:
                rules.pop(0)
                continue
            if j < 0:
                break
            pos = j + len(pat)
            rules.pop(0)
            if ans.startswith("<pause>"):
                time.sleep(3)
                ans = ans[len("<pause>"):]
            if ans == "<detach>":
                time.sleep(1)
                ans = "\x10\x11"
            if ans:
                os.write(fd, ans.encode().decode("unicode_escape").encode())
        if not rules:
            break
    if rules:
        sys.stderr.write("\nexpect.py: not seen within %ds: %r\n" % (timeout, rules[0][0]))
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        sys.exit(1)
    # Every rule matched: drain the output until the command exits.
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                b = os.read(fd, 4096)
            except OSError:
                b = b""
            if not b:
                break
            sys.stdout.write(b.decode(errors="replace"))
            sys.stdout.flush()
    if time.time() >= deadline:
        sys.stderr.write("\nexpect.py: the command did not exit within %ds\n" % timeout)
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    _, status = os.waitpid(pid, 0)
    sys.exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 1)


if __name__ == "__main__":
    main()
