#!/usr/bin/env python3
"""Send one newline-delimited JSON request to the daemon control socket and print
the response. Used by the README demo (scripts/demo/play.sh) to show the data-vault
round-trip (tokenize on the way to the agent, detokenize at an authorized egress)."""
import json
import socket
import sys

sock_path = sys.argv[1]
request = sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
f = s.makefile("rwb")
f.write((request.strip() + "\n").encode())
f.flush()
sys.stdout.write(f.readline().decode())
