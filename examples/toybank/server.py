#!/usr/bin/env python3
"""A toy "bank" MCP server (stdio JSON-RPC) for the Guardian broker demo.

It exposes two tools — `get_balance` (read) and `transfer` (move money) — both of
which REQUIRE a valid `auth_token` in the arguments. The point of the demo: the
agent never knows the token; Guardian's broker injects it into allowed calls, and
Guardian's policy blocks `transfer` (money movement) before it ever reaches here.
"""
import sys
import json

EXPECTED_TOKEN = "the-bank-token"  # demo only; in reality this lives in Guardian's broker
TOOLS = [
    {"name": "get_balance", "description": "Read the account balance", "inputSchema": {"type": "object"}},
    {"name": "transfer", "description": "Transfer money to a recipient", "inputSchema": {"type": "object"}},
]


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def result(mid, text, is_error=False):
    send({"jsonrpc": "2.0", "id": mid, "result": {
        "content": [{"type": "text", "text": text}], "isError": is_error}})


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    mid = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}
    if mid is None:  # a notification (e.g. notifications/initialized)
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": "toybank", "version": "0.1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if args.get("auth_token") != EXPECTED_TOKEN:
            result(mid, "UNAUTHORIZED: missing or invalid bank token", is_error=True)
        elif name == "get_balance":
            result(mid, "balance: EUR 4242.00")
        elif name == "transfer":
            result(mid, "TRANSFERRED — if you see this, Guardian failed to block it!")
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown tool"}})
    else:
        send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})
