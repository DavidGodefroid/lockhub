#!/usr/bin/env python3
"""Answers a lock console's start-up questions through `lox attach`.

    attach.py TIMEOUT FIRST UNTIL [PATTERN ANSWER]... -- CMD...

CMD (lox attach NAME) runs at a pseudo-terminal. The question pending
when it attaches is not replayed (the consoles have no log): FIRST is
typed once attached. Then each later PATTERN seen in the output is answered
with ANSWER, once; once UNTIL is seen, the terminal is detached (Ctrl-P
Ctrl-Q) and the exit status is 0. The output is copied to stdout. Exit 1
when UNTIL is not seen within TIMEOUT seconds. Answers take \\n escapes.
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
    timeout, first, until = float(head[0]), head[1], head[2]
    rules = [(head[i], head[i + 1]) for i in range(3, len(head), 2)]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    out = ""
    seen = 0  # output answered up to here
    deadline = time.time() + timeout
    time.sleep(3)
    os.write(fd, first.encode().decode("unicode_escape").encode())
    ok = False
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                b = os.read(fd, 4096)
            except OSError:
                break
            if not b:
                break
            s = b.decode(errors="replace")
            sys.stdout.write(s)
            sys.stdout.flush()
            out += s
        for i, (pat, ans) in enumerate(rules):
            j = out.find(pat, seen)
            if pat and j >= 0:
                os.write(fd, ans.encode().decode("unicode_escape").encode())
                seen = j + len(pat)
                rules[i] = ("", ans)
        if until in out:
            ok = True
            break
    time.sleep(1)
    try:
        os.write(fd, b"\x10\x11")
    except OSError:
        pass
    time.sleep(2)
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
