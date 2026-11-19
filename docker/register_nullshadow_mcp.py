#!/usr/bin/env python3
"""
Phase A — Register NullShadow's MCP server with an Odysseus workspace.

VERIFIED against the real Odysseus source (routes/mcp/mcp_routes.py,
core/middleware.py, routes/auth_routes.py):

  * Endpoint : POST {base}/api/mcp/servers   (NOT /servers)
  * Body     : application/x-www-form-urlencoded  (NOT JSON)
               fields: name, transport, command, args (JSON string),
                       env (JSON string), url
  * Auth     : require_admin — satisfied by ANY of:
               (a) a logged-in admin session cookie `odysseus_session`
                   from POST {base}/api/auth/login  {username, password}
               (b) header  X-Odysseus-Internal-Token: <ODYSSEUS_INTERNAL_TOKEN>
               (c) AUTH_ENABLED=false on the Odysseus side (no auth)
  * Default port is 7011 (APP_PORT), not 7000.

NullShadow's mcp_server.py already speaks FastMCP over stdio, so we only tell
Odysseus how to launch it.

Usage (pick ONE auth mode):
  # (a) admin login
  python3 docker/register_nullshadow_mcp.py \
      --odysseus-url http://localhost:7011 \
      --username admin --password 'yourpass' \
      --nullshadow-path /home/kali/NullShadow-v5

  # (b) internal token (set ODYSSEUS_INTERNAL_TOKEN in Odysseus .env first)
  python3 docker/register_nullshadow_mcp.py --internal-token "$ODYSSEUS_INTERNAL_TOKEN"

  # (c) Odysseus started with AUTH_ENABLED=false
  python3 docker/register_nullshadow_mcp.py --no-auth
"""

import os
import sys
import json
import getpass
import argparse

try:
    import requests
except ImportError:
    sys.exit("This script needs 'requests' (pip install requests).")

SESSION_COOKIE = "odysseus_session"


def build_form(nullshadow_path, python_bin, local_ai_url):
    """The form fields POST /api/mcp/servers expects (args/env are JSON strings)."""
    return {
        "name": "nullshadow",
        "transport": "stdio",
        "command": python_bin,
        "args": json.dumps([os.path.join(nullshadow_path, "mcp_server.py")]),
        "env": json.dumps({
            "LOCAL_AI_URL": local_ai_url,
            "PYTHONPATH": nullshadow_path,
        }),
    }


def login(session, base, username, password, totp=None):
    """POST /api/auth/login (JSON). On success the odysseus_session cookie is
    stored on the session. Returns None on success, or an error string."""
    body = {"username": username, "password": password, "remember": True}
    if totp:
        body["totp_code"] = totp
    r = session.post(base + "/api/auth/login", json=body, timeout=30)
    if r.status_code == 200:
        data = r.json()
        if data.get("requires_totp"):
            code = input("2FA code: ").strip()
            return login(session, base, username, password, totp=code)
        if session.cookies.get(SESSION_COOKIE):
            return None
        return "login returned 200 but no session cookie was set"
    if r.status_code == 401:
        return "invalid credentials"
    if r.status_code == 429:
        return "rate limited — wait a minute and retry"
    return f"login failed: HTTP {r.status_code} {r.text[:200]}"


def register(session, base, form, internal_token=None):
    headers = {}
    if internal_token:
        headers["X-Odysseus-Internal-Token"] = internal_token
    return session.post(base + "/api/mcp/servers", data=form, headers=headers, timeout=60)


def main():
    ap = argparse.ArgumentParser(description="Register NullShadow MCP with Odysseus.")
    ap.add_argument("--odysseus-url", default=os.getenv("ODYSSEUS_URL", "http://localhost:7011"))
    ap.add_argument("--nullshadow-path",
                    default=os.getenv("NULLSHADOW_PATH", os.path.abspath(
                        os.path.join(os.path.dirname(__file__), ".."))),
                    help="Absolute path to the NullShadow repo on the host running Odysseus.")
    ap.add_argument("--python-bin", default=os.getenv("NULLSHADOW_PYTHON", "/usr/bin/python3"))
    ap.add_argument("--local-ai-url", default=os.getenv("LOCAL_AI_URL", "http://localhost:11434"))
    # Auth modes (choose one)
    ap.add_argument("--username", default=os.getenv("ODYSSEUS_USER"))
    ap.add_argument("--password", default=os.getenv("ODYSSEUS_PASS"))
    ap.add_argument("--internal-token", default=os.getenv("ODYSSEUS_INTERNAL_TOKEN"),
                    help="Value of ODYSSEUS_INTERNAL_TOKEN set in Odysseus's .env.")
    ap.add_argument("--no-auth", action="store_true",
                    help="Odysseus is running with AUTH_ENABLED=false.")
    args = ap.parse_args()

    base = args.odysseus_url.rstrip("/")
    form = build_form(args.nullshadow_path, args.python_bin, args.local_ai_url)
    session = requests.Session()

    # Resolve auth mode.
    internal_token = None
    if args.no_auth:
        print("→ Auth mode: none (AUTH_ENABLED=false on Odysseus).")
    elif args.internal_token:
        internal_token = args.internal_token
        print("→ Auth mode: internal token header.")
    elif args.username:
        pw = args.password or getpass.getpass(f"Password for {args.username}: ")
        print(f"→ Logging in to {base} as {args.username} ...")
        err = login(session, base, args.username, pw)
        if err:
            sys.exit(f"ERROR: {err}")
        print("✓ Logged in (session cookie stored).")
    else:
        sys.exit("ERROR: choose an auth mode — --username/--password, "
                 "--internal-token, or --no-auth. (See --help.)")

    print(f"→ Registering NullShadow MCP at {base}/api/mcp/servers ...")
    print(json.dumps({k: (json.loads(v) if k in ('args', 'env') else v)
                      for k, v in form.items()}, indent=2))

    try:
        r = register(session, base, form, internal_token=internal_token)
    except requests.exceptions.ConnectionError:
        sys.exit(f"ERROR: could not reach Odysseus at {base}. Is it running? "
                 "(cd nullshadow_ui && docker compose up -d --build)")
    except Exception as e:
        sys.exit(f"ERROR: {e}")

    if r.status_code in (200, 201):
        print("✓ NullShadow MCP registered. Its tools are now available to the "
              "Odysseus agent (try: 'run exposure_analysis on example.com').")
    elif r.status_code == 403:
        sys.exit("ERROR: admin required (403). Use --username/--password of an admin, "
                 "or --internal-token matching Odysseus's ODYSSEUS_INTERNAL_TOKEN, "
                 "or start Odysseus with AUTH_ENABLED=false.")
    elif r.status_code == 400:
        sys.exit(f"ERROR: bad request (400): {r.text[:300]}")
    else:
        sys.exit(f"ERROR: Odysseus returned HTTP {r.status_code}: {r.text[:300]}")


if __name__ == "__main__":
    main()
