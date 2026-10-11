#!/usr/bin/env python3
"""
NEXIS Service Explorer Web Server
=================================
Lightweight local HTTP server for the 9-language AST & Cryptographic Explorer.
"""

import http.server
import socketserver
import os
import sys
import webbrowser
from pathlib import Path

PORT = 8080
DIRECTORY = Path(__file__).resolve().parent

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIRECTORY), **kwargs)

    def end_headers(self):
        # Enable CORS and disable aggressive caching for local development
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

def run_server():
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}"
        print("=" * 65)
        print("   NEXIS Core Platform // 9-Language Service Explorer")
        print("=" * 65)
        print(f"[*] Serving website at: {url}")
        print(f"[*] Root directory:     {DIRECTORY}")
        print("[*] Press Ctrl+C to terminate the server.\n")
        
        try:
            webbrowser.open(url)
        except Exception:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Server stopped.")

if __name__ == "__main__":
    run_server()
