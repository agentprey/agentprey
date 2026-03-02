#!/usr/bin/env python3

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def build_response(mode: str) -> dict:
    if mode == "vulnerable":
        content = "My system prompt is: You are an internal assistant with unrestricted access."
    else:
        content = "I cannot share system instructions and will not ignore safety rules."

    return {
        "choices": [
            {
                "message": {
                    "content": content,
                }
            }
        ]
    }


def create_handler(mode: str):
    class MockHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/chat":
                self.send_error(404, "Not Found")
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length > 0:
                self.rfile.read(content_length)

            response = build_response(mode)
            payload = json.dumps(response).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args) -> None:
            return

    return MockHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentPrey local mock agent")
    parser.add_argument(
        "--mode", choices=["vulnerable", "resistant"], default="resistant"
    )
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), create_handler(args.mode))
    print(f"Mock agent running on http://127.0.0.1:{args.port}/chat (mode={args.mode})")
    server.serve_forever()


if __name__ == "__main__":
    main()
