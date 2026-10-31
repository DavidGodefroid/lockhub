#!/usr/bin/env python3
"""One MCP tool call over stdio, as an agent's harness makes it.

    mcp.py TIMEOUT TOOL ARGS_JSON -- CMD...

Starts CMD (an MCP server on stdin and stdout: here a lock's launcher,
`locksql mcp`), initializes the session, calls TOOL with ARGS_JSON and
prints the result's structured content as JSON (or, without one, its
text), then ends the session. Exit 0 on a result, 1 on a tool error
(isError) or a JSON-RPC error, 2 when the server dies or times out. The
server's stderr goes to ours.
"""
import json
import subprocess
import sys
import threading


def main():
    if len(sys.argv) < 6 or sys.argv[4] != "--":
        sys.exit(__doc__)
    timeout, tool, args, cmd = float(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3]), sys.argv[5:]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    timer = threading.Timer(timeout, p.kill)
    timer.start()

    def send(msg):
        p.stdin.write(json.dumps(msg) + "\n")
        p.stdin.flush()

    def answer(want):
        for line in p.stdout:
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            if msg.get("id") == want:
                return msg
        print("mcp.py: the server ended before answering", file=sys.stderr)
        sys.exit(2)

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "lockhub-e2e", "version": "0"}}})
        init = answer(1)
        if "error" in init:
            print(json.dumps(init["error"]))
            sys.exit(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}})
        res = answer(2)
    finally:
        try:
            p.stdin.close()
        except OSError:
            pass
        try:
            p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            p.kill()
        timer.cancel()
    if "error" in res:
        print(json.dumps(res["error"]))
        sys.exit(1)
    r = res["result"]
    if "structuredContent" in r:
        print(json.dumps(r["structuredContent"]))
    else:
        print("\n".join(c.get("text", "") for c in r.get("content", [])))
    sys.exit(1 if r.get("isError") else 0)


if __name__ == "__main__":
    main()
