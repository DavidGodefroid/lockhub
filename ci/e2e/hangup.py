#!/usr/bin/env python3
"""Closes the terminal of `lox attach` while it is attached.

    hangup.py TIMEOUT -- CMD...

CMD (lox attach NAME) runs at a pseudo-terminal. Once it says how to
detach, the terminal is closed (a hang-up, as when the user closes the
window) without typing anything. The output is copied to stdout. Exit 0
once CMD ended, 1 when it did not say how to detach or did not end within
TIMEOUT seconds.
"""
import os
import pty
import select
import sys
import time


def main():
    args = sys.argv[1:]
    cut = args.index("--")
    timeout, cmd = float(args[0]), args[cut + 1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(cmd[0], cmd)
    out = ""
    deadline = time.time() + timeout
    while "Ctrl-P Ctrl-Q detaches" not in out and time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                b = os.read(fd, 4096)
            except OSError:
                break
            if not b:
                break
            out += b.decode(errors="replace")
    sys.stdout.write(out)
    attached = "Ctrl-P Ctrl-Q detaches" in out
    time.sleep(2)  # docker's attach is up
    os.close(fd)
    while time.time() < deadline:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            sys.exit(0 if attached else 1)
        time.sleep(0.2)
    os.kill(pid, 9)
    sys.exit(1)


if __name__ == "__main__":
    main()
