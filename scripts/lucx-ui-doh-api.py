#!/usr/bin/env python3
"""Safe additive LucX-UI DoH integration through the panel API.

The adapter never writes the panel SQLite database or runtime Xray config.
When --base-url is omitted, it reads only endpoint settings from SQLite in
read-only mode to discover the local panel URL. Panel authorization is resolved
locally from the installer's root-only credential file or a dedicated token
provisioned by the LucX-UI CLI; operators are never prompted to paste a Bearer token.
Xray settings are read through the panel API; updates require explicit approval
of the possible Xray restart.
"""

from __future__ import annotations

import argparse
import copy
import http.client
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, Request, build_opener, urlopen

# Shared, side-effect-free semantic Xray DNS planner.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from xray_dns_planner import build_dns_plan, _outbound_matches_dns_endpoint, _server_endpoint

VERSION = "1.6.0"
DEFAULT_PLUGIN_SERVICE = "lucx-plugin-doh-health-monitor"
DEFAULT_PLUGIN_STATUS_URL = "http://127.0.0.1:18765/status"
DEFAULT_PLUGIN_PORT = 5355
# Add only Xray versions that passed staging validation. Empty means warn on all.
VERIFIED_XRAY_VERSIONS: frozenset[str] = frozenset()
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
INSTALL_RESULT_FILE = Path("/etc/x-ui/install-result.env")
DEFAULT_PANEL_AUTH_FILE = Path("/var/lib/doh-health-monitor-panel-auth/panel-api-auth.json")
PANEL_AUTH_TOKEN_NAME = "doh-health-monitor-integration"

DNS_OUT = {
    "tag": "dns-out",
    "protocol": "dns",
    "settings": {
        "rewriteNetwork": "udp",
        "rewriteAddress": "127.0.0.1",
        "rewritePort": 5355,
    },
}
DNS_SERVER = {
    "address": "127.0.0.1",
    "port": 5355,
    "domains": [],
    "skipFallback": False,
}
DNS_PORT_RULE = {
    "enabled": True,
    "network": "tcp,udp",
    "outboundTag": "dns-out",
    "port": "53",
    "ruleTag": "doh-health-monitor-dns-port53",
    "type": "field",
}
DNS_ALLOW_TAG = "xui-dns-allow"
TEMP_DNS_FINAL_RULE = {
    "action": "allow",
    "network": "tcp,udp",
    "port": "5355",
    "ip": ["127.0.0.1"],
}


class IntegrationError(RuntimeError):
    pass


def _safe_exception_summary(exc: Exception) -> str:
    """Return useful exception diagnostics without exposing common credential forms."""
    detail = str(exc).strip()
    detail = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1[redacted]", detail)
    detail = re.sub(
        r"(?i)\b(token|password|passwd|authorization|apikey|secret)\b([\s:=]+)[^\s,;]+",
        r"\1\2[redacted]",
        detail,
    )
    detail = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", detail)
    if len(detail) > 240:
        detail = detail[:237] + "..."
    exception_type = type(exc).__name__
    return f"{exception_type}: {detail}" if detail else exception_type


def parse_xray_version(output: str) -> str | None:
    """Extract the Xray core version without exposing command output."""
    match = re.search(r"\bXray\s+v?(\d+(?:\.\d+){1,3})\b", output, re.IGNORECASE)
    return match.group(1) if match else None


def xray_version_is_verified(version: str) -> bool:
    return version in VERIFIED_XRAY_VERSIONS


def find_xray_binary(explicit_path: str | None = None) -> str:
    """Find the running Xray executable, then common panel/system paths."""
    candidates: list[str] = []
    if explicit_path:
        candidates.append(explicit_path)
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                exe = os.readlink(entry / "exe")
            except OSError:
                continue
            if "xray" in Path(exe.removesuffix(" (deleted)")).name.lower():
                candidates.append(str(entry / "exe"))
    except OSError:
        pass
    candidates.extend([
        "/usr/local/x-ui/bin/xray",
        "/usr/local/x-ui/xray",
        "/usr/bin/xray",
        "/usr/local/bin/xray",
    ])
    located = shutil.which("xray")
    if located:
        candidates.append(located)
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise IntegrationError("Xray executable was not detected; use --xray-bin with the installed Xray binary")


def read_xray_version(binary: str) -> str:
    """Run the local Xray binary and return only its parsed version."""
    for argument in ("version", "-version"):
        try:
            result = subprocess.run(
                [binary, argument],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        version = parse_xray_version(result.stdout or "")
        if version:
            return version
    raise IntegrationError("Could not determine Xray version from the installed binary")


def detect_panel_version() -> str | None:
    """Best-effort informational LucX-UI version lookup; never a compatibility gate."""
    candidates = ["/usr/local/x-ui/x-ui"]
    located = shutil.which("x-ui")
    if located:
        candidates.append(located)
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file() or not os.access(path, os.X_OK):
            continue
        try:
            result = subprocess.run(
                [str(path), "-v"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        match = re.search(r"\b(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)\b", result.stdout or "")
        if match:
            return match.group(1)
    return None




@dataclass(frozen=True)
class PanelEndpoint:
    base_url: str
    host_header: str | None = None
    tls_server_name: str | None = None
    tls_verify_ip: str | None = None


def _running_panel_context() -> tuple[dict[str, str], Path]:
    """Read only the non-secret runtime settings needed to locate x-ui's DB."""
    keys = {"XUI_PORT", "XUI_DB_FOLDER", "XUI_DB_TYPE"}
    env = {key: os.environ[key] for key in keys if key in os.environ}
    panel_cwd = Path("/usr/local/x-ui")
    matches: list[tuple[dict[str, str], Path, str]] = []
    try:
        proc_entries = list(Path("/proc").iterdir())
    except OSError:
        return env, panel_cwd

    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        try:
            executable = os.readlink(entry / "exe").removesuffix(" (deleted)")
            if Path(executable).name != "x-ui":
                continue
            raw = (entry / "environ").read_bytes()
            process_env: dict[str, str] = {}
            for item in raw.split(b"\0"):
                if b"=" not in item:
                    continue
                key_raw, value_raw = item.split(b"=", 1)
                key = key_raw.decode("ascii", errors="ignore")
                if key in keys:
                    process_env[key] = value_raw.decode("utf-8", errors="replace")
            cwd = Path(os.readlink(entry / "cwd"))
            matches.append((process_env, cwd, executable))
        except OSError:
            continue

    if matches:
        preferred = [item for item in matches if item[2] == "/usr/local/x-ui/x-ui"]
        if preferred:
            matches = preferred
        if len(matches) > 1:
            snapshots = {(tuple(sorted(item[0].items())), str(item[1])) for item in matches}
            if len(snapshots) > 1:
                raise IntegrationError("Multiple LucX-UI processes have different runtime settings; specify --base-url and --panel-db")
        process_env, panel_cwd, _ = matches[0]
        env.update(process_env)
    return env, panel_cwd


def _read_secure_text_file(path: Path, *, expected_uid: int | None = None, max_bytes: int = 65536) -> str | None:
    """Read a root-owned, private regular file without following symlinks."""
    if expected_uid is None:
        expected_uid = os.geteuid()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError:
        raise IntegrationError(f"Could not safely open local credential file: {path}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise IntegrationError(f"Credential path is not a regular file: {path}")
        if info.st_uid != expected_uid or info.st_mode & 0o077:
            raise IntegrationError(f"Credential file must be owned by uid {expected_uid} and have mode 0600 or stricter: {path}")
        if info.st_size > max_bytes:
            raise IntegrationError(f"Credential file is unexpectedly large: {path}")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            content = stream.read(max_bytes + 1)
        if len(content.encode("utf-8")) > max_bytes:
            raise IntegrationError(f"Credential file is unexpectedly large: {path}")
        return content
    except UnicodeError:
        raise IntegrationError(f"Credential file is not valid UTF-8: {path}") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _validate_api_token(token: str) -> str:
    value = token.strip()
    if len(value) < 32 or any(char.isspace() for char in value):
        raise IntegrationError("LucX-UI API credential is empty or has an invalid format")
    return value


def load_installer_api_token(
    path: Path = INSTALL_RESULT_FILE, *, expected_uid: int | None = None
) -> str | None:
    """Read XUI_API_TOKEN from the installer's private env file without sourcing shell code."""
    content = _read_secure_text_file(path, expected_uid=expected_uid)
    if content is None:
        return None
    for line in content.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "XUI_API_TOKEN":
            try:
                parts = shlex.split(value, comments=False, posix=True)
            except ValueError:
                raise IntegrationError("XUI_API_TOKEN in LucX-UI install result is malformed") from None
            if len(parts) != 1:
                raise IntegrationError("XUI_API_TOKEN in LucX-UI install result is malformed")
            return _validate_api_token(parts[0])
    return None


def load_saved_panel_api_token(path: Path, *, expected_uid: int | None = None) -> str | None:
    """Load the adapter's own persisted API credential, never another panel token."""
    content = _read_secure_text_file(path, expected_uid=expected_uid)
    if content is None:
        return None
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        raise IntegrationError("Saved LucX-UI API credential file is malformed") from None
    if (
        not isinstance(payload, dict)
        or payload.get("format") != 1
        or payload.get("token_name") != PANEL_AUTH_TOKEN_NAME
        or not isinstance(payload.get("token"), str)
    ):
        raise IntegrationError("Saved LucX-UI API credential file has an unsupported format")
    return _validate_api_token(payload["token"])


def save_panel_api_token(path: Path, token: str, *, expected_uid: int | None = None) -> None:
    """Persist a newly minted adapter token atomically in a root-only file."""
    token = _validate_api_token(token)
    if expected_uid is None:
        expected_uid = os.geteuid()
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = parent.stat()
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != expected_uid:
            raise IntegrationError("LucX-UI credential directory must be a root-owned directory")
        if parent_info.st_mode & 0o077:
            raise IntegrationError("LucX-UI credential directory must have mode 0700 or stricter")
        payload = json.dumps(
            {"format": 1, "token_name": PANEL_AUTH_TOKEN_NAME, "token": token},
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        fd, temporary_name = tempfile.mkstemp(prefix=".panel-api-auth-", dir=str(parent))
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if path.exists() or path.is_symlink():
                raise IntegrationError("Refusing to overwrite an existing LucX-UI credential file")
            os.replace(temporary, path)
            directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    except IntegrationError:
        raise
    except OSError:
        raise IntegrationError("Could not persist LucX-UI API credential securely") from None


def detect_panel_cli(panel_cwd: Path | None = None) -> Path:
    """Find the running LucX-UI executable, independent of its installation directory."""
    running: set[Path] = set()
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        entries = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            executable = os.readlink(entry / "exe").removesuffix(" (deleted)")
        except OSError:
            continue
        candidate = Path(executable)
        if candidate.name == "x-ui" and candidate.is_file() and os.access(candidate, os.X_OK):
            running.add(candidate)
    if len(running) > 1:
        raise IntegrationError("Multiple LucX-UI executables are running; cannot choose a local API-token provider safely")
    if running:
        return next(iter(running))

    candidates: list[Path] = []
    if panel_cwd is not None:
        candidates.append(panel_cwd / "x-ui")
    located = shutil.which("x-ui")
    if located:
        candidates.append(Path(located))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise IntegrationError("Could not locate the running LucX-UI CLI to provision a local API credential")


def mint_panel_api_token(panel_cli: Path, auth_file: Path) -> str:
    """Create this adapter's dedicated admin token via LucX-UI's local CLI."""
    try:
        help_result = subprocess.run(
            [str(panel_cli), "setting", "-h"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise IntegrationError("Could not inspect the local LucX-UI API-token CLI") from None
    help_text = help_result.stdout or ""
    if not all(flag in help_text for flag in ("-getApiToken", "-tokenName", "-tokenScope")):
        raise IntegrationError(
            "This LucX-UI build does not expose non-interactive API-token provisioning; "
            "no API token was requested or changed"
        )
    try:
        result = subprocess.run(
            [
                str(panel_cli), "setting", "-getApiToken",
                "-tokenName", PANEL_AUTH_TOKEN_NAME,
                "-tokenScope", "admin",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise IntegrationError("LucX-UI could not provision its local integration API credential") from None
    match = re.search(r"(?m)^apiToken:\s*(\S+)\s*$", result.stdout or "")
    if result.returncode != 0 or not match:
        raise IntegrationError(
            "LucX-UI did not return a new API credential; no panel Xray settings were changed"
        )
    token = _validate_api_token(match.group(1))
    save_panel_api_token(auth_file, token)
    print(
        "PASS: created a dedicated LucX-UI API credential for this integration "
        f"({PANEL_AUTH_TOKEN_NAME}, admin scope); stored locally with mode 0600"
    )
    return token


def resolve_panel_api_token(
    auth_file: Path = DEFAULT_PANEL_AUTH_FILE,
    *,
    installer_file: Path = INSTALL_RESULT_FILE,
    environ: dict[str, str] | None = None,
    panel_cli: Path | None = None,
    panel_cwd: Path | None = None,
) -> str:
    """Obtain panel authorization locally; never prompt the operator for a Bearer token."""
    env = os.environ if environ is None else environ
    supplied = env.get("XUI_API_TOKEN", "").strip()
    if supplied:
        print("PASS: using XUI_API_TOKEN supplied by the service environment")
        return _validate_api_token(supplied)

    installer_token = load_installer_api_token(installer_file)
    if installer_token:
        print("PASS: loaded the installer-provided LucX-UI API credential (secret hidden)")
        return installer_token

    saved_token = load_saved_panel_api_token(auth_file)
    if saved_token:
        print("PASS: reusing the protected local LucX-UI integration credential")
        return saved_token

    cli = panel_cli or detect_panel_cli(panel_cwd)
    return mint_panel_api_token(cli, auth_file)


def _read_panel_endpoint_settings(database_path: Path) -> dict[str, str]:
    """Read only the web endpoint keys; SQLite is opened strictly mode=ro."""
    if not database_path.is_file():
        raise IntegrationError("LucX-UI SQLite database for endpoint discovery was not found; specify --base-url")
    uri = database_path.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=3)
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = connection.execute(
                "SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)",
                ("webPort", "webBasePath", "webCertFile", "webKeyFile", "webDomain"),
            ).fetchall()
        finally:
            connection.close()
    except (OSError, sqlite3.Error):
        raise IntegrationError("Could not read LucX-UI endpoint settings from SQLite in read-only mode; specify --base-url") from None
    return {str(key): "" if value is None else str(value) for key, value in rows}


def _resolve_panel_file(value: str, panel_cwd: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else panel_cwd / path


def _panel_tls_is_enabled(cert_file: str, key_file: str, panel_cwd: Path) -> bool:
    if not cert_file and not key_file:
        return False
    if not cert_file or not key_file:
        raise IntegrationError(
            "LucX-UI has an incomplete TLS certificate/key configuration; refusing HTTP fallback"
        )
    cert_path = _resolve_panel_file(cert_file, panel_cwd)
    key_path = _resolve_panel_file(key_file, panel_cwd)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        return True
    except (OSError, ssl.SSLError):
        raise IntegrationError(
            "LucX-UI TLS certificate/key could not be loaded; refusing HTTP fallback"
        ) from None


def _panel_certificate_sans(cert_file: str, panel_cwd: Path) -> list[tuple[str, str]]:
    """Read the leaf certificate SANs used by LucX-UI without loading its private key."""
    cert_path = _resolve_panel_file(cert_file, panel_cwd)
    try:
        decoded = ssl._ssl._test_decode_cert(str(cert_path))
    except (AttributeError, OSError, ssl.SSLError, ValueError):
        raise IntegrationError(
            "Could not inspect the configured LucX-UI certificate SANs; specify --tls-mode and --tls-name"
        ) from None
    sans = decoded.get("subjectAltName", ())
    return [
        (str(kind), str(value))
        for kind, value in sans
        if isinstance(kind, str) and isinstance(value, str)
    ]


def verify_certificate_ip_san(certificate: dict, expected_ip: str) -> None:
    """Require an exact IP Address SAN; never fall back to the certificate CN."""
    try:
        wanted = ipaddress.ip_address(expected_ip)
        for kind, value in certificate.get("subjectAltName", ()):
            if kind == "IP Address" and ipaddress.ip_address(value) == wanted:
                return
    except (TypeError, ValueError):
        pass
    raise ssl.CertificateError(
        f"certificate does not contain the expected IP subjectAltName {expected_ip}"
    )


def _normalize_panel_base_path(value: str) -> str:
    path = (value or "/").strip()
    if not path:
        path = "/"
    if any(ord(char) < 32 or char in "?#\\ " for char in path):
        raise IntegrationError("LucX-UI webBasePath contains unsupported URL characters")
    if not path.startswith("/"):
        path = "/" + path
    segments = [segment for segment in path.split("/") if segment]
    if any(segment in {".", ".."} for segment in segments):
        raise IntegrationError("LucX-UI webBasePath contains a relative path segment")
    return "/" + "/".join(segments) + ("/" if segments else "")


def detect_panel_endpoint(
    panel_db: Path | None = None,
    runtime_env: dict[str, str] | None = None,
    panel_cwd: Path | None = None,
) -> PanelEndpoint:
    """Detect the local LucX-UI URL without writing its database or settings."""
    if runtime_env is None:
        runtime_env, detected_cwd = _running_panel_context()
        if panel_cwd is None:
            panel_cwd = detected_cwd
    else:
        runtime_env = dict(runtime_env)
    if panel_cwd is None:
        panel_cwd = Path("/usr/local/x-ui")

    if panel_db is None:
        db_type = runtime_env.get("XUI_DB_TYPE", "sqlite").strip().lower() or "sqlite"
        if db_type not in {"sqlite", "sqlite3"}:
            raise IntegrationError("Automatic endpoint discovery currently supports SQLite only; specify --base-url for PostgreSQL panels")
        db_folder = Path(runtime_env.get("XUI_DB_FOLDER", "/etc/x-ui")).expanduser()
        if not db_folder.is_absolute():
            db_folder = panel_cwd / db_folder
        panel_db = db_folder / "x-ui.db"
    settings = _read_panel_endpoint_settings(panel_db)

    stored_port = settings.get("webPort", "") or "2053"
    try:
        port = int(stored_port)
    except ValueError:
        raise IntegrationError("LucX-UI webPort setting is invalid; specify --base-url") from None
    override = runtime_env.get("XUI_PORT", "").strip()
    if override:
        try:
            override_port = int(override)
            if 1 <= override_port <= 65535:
                port = override_port
        except ValueError:
            pass  # LucX-UI ignores an invalid XUI_PORT and falls back to webPort.
    if not 1 <= port <= 65535:
        raise IntegrationError("LucX-UI panel port is outside the valid range; specify --base-url")

    base_path = _normalize_panel_base_path(settings.get("webBasePath", "/"))
    scheme = "https" if _panel_tls_is_enabled(
        settings.get("webCertFile", ""),
        settings.get("webKeyFile", ""),
        panel_cwd,
    ) else "http"

    domain = settings.get("webDomain", "").strip()
    host_header = None
    tls_server_name = None
    tls_verify_ip = None
    if domain:
        parsed_domain = urlsplit("//" + domain)
        try:
            explicit_domain_port = parsed_domain.port
        except ValueError:
            explicit_domain_port = -1
        if (
            not parsed_domain.hostname
            or parsed_domain.username
            or parsed_domain.password
            or explicit_domain_port is not None
            or parsed_domain.path
            or parsed_domain.query
            or parsed_domain.fragment
            or any(char.isspace() for char in domain)
        ):
            raise IntegrationError("LucX-UI webDomain is not a plain hostname; specify --base-url")
        host = parsed_domain.hostname
        try:
            parsed_ip = ipaddress.ip_address(host)
            host_for_header = f"[{host}]" if parsed_ip.version == 6 else host
            if scheme == "https":
                tls_server_name = "localhost"
                tls_verify_ip = str(parsed_ip)
        except ValueError:
            host_for_header = host
            if scheme == "https":
                tls_server_name = host
        host_header = f"{host_for_header}:{port}"
    elif scheme == "https":
        sans = _panel_certificate_sans(settings.get("webCertFile", ""), panel_cwd)
        ip_sans = [value for kind, value in sans if kind == "IP Address"]
        dns_sans = [value for kind, value in sans if kind == "DNS"]
        if ip_sans:
            tls_verify_ip = str(ipaddress.ip_address(ip_sans[0]))
            tls_server_name = "localhost"
        elif dns_sans:
            tls_server_name = dns_sans[0]
        else:
            raise IntegrationError(
                "Configured LucX-UI TLS certificate has no DNS/IP SAN; specify --tls-mode and --tls-name"
            )

    url_path = base_path.rstrip("/")
    base_url = f"{scheme}://127.0.0.1:{port}{url_path}"
    return PanelEndpoint(base_url, host_header, tls_server_name, tls_verify_ip)


class _PanelSNIHTTPSConnection(http.client.HTTPSConnection):
    """Connect to loopback with a separate SNI name and optional IP SAN identity."""

    def __init__(self, host, *args, server_hostname: str, verify_ip: str | None = None, **kwargs):
        self._panel_server_hostname = server_hostname
        self._panel_verify_ip = verify_ip
        super().__init__(host, *args, **kwargs)

    def connect(self):
        http.client.HTTPConnection.connect(self)
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=self._panel_server_hostname,
        )
        if self._panel_verify_ip:
            try:
                verify_certificate_ip_san(self.sock.getpeercert(), self._panel_verify_ip)
            except ssl.CertificateError:
                self.sock.close()
                raise


class _PanelSNIHTTPSHandler(HTTPSHandler):
    def __init__(self, server_hostname: str, verify_ip: str | None = None):
        context = ssl.create_default_context()
        if verify_ip:
            # Keep CERT_REQUIRED chain validation. Only built-in hostname
            # matching is replaced by an explicit strict IP SAN check.
            context.check_hostname = False
        super().__init__(context=context)
        self._panel_server_hostname = server_hostname
        self._panel_verify_ip = verify_ip

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: _PanelSNIHTTPSConnection(
                host,
                server_hostname=self._panel_server_hostname,
                verify_ip=self._panel_verify_ip,
                **kwargs,
            ),
            request,
            # Pass the HTTPSHandler's configured SSL context through to the
            # custom connection. Without this, HTTPSConnection creates its
            # own default context and re-enables hostname matching against
            # the SNI name (localhost), bypassing the strict IP-SAN mode.
            context=self._context,
        )


def listener_output_has_loopback_port(output: str, port: int) -> bool:
    """Recognize a listener bound specifically to IPv4/IPv6 loopback."""
    pattern = re.compile(
        rf"(?:127\.0\.0\.1|\[?::1\]?):{port}(?:\s|$)"
    )
    return any(pattern.search(line) for line in output.splitlines())


def validate_plugin_status(body: bytes) -> dict:
    if len(body) > 1024 * 1024:
        raise IntegrationError("DoH Health Monitor status response exceeded the size limit")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("DoH Health Monitor status endpoint returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise IntegrationError("DoH Health Monitor status endpoint did not return a JSON object")
    return payload


def check_plugin_health(service: str, status_url: str, port: int) -> None:
    """Fail closed unless the installed plugin service, status API and both listeners work."""
    if not service or not re.fullmatch(r"[A-Za-z0-9_.@-]+", service):
        raise IntegrationError("Invalid systemd service name for DoH Health Monitor")
    if not panel_api_is_local(status_url):
        raise IntegrationError("DoH Health Monitor status URL must use localhost/loopback")
    systemctl = shutil.which("systemctl")
    ss = shutil.which("ss")
    if not systemctl or not ss:
        raise IntegrationError("Required preflight tools systemctl and ss were not found")
    try:
        load_state = subprocess.run(
            [systemctl, "show", "--property=LoadState", "--value", service],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
        if load_state.returncode != 0 or (load_state.stdout or "").strip() != "loaded":
            raise IntegrationError(
                f"DoH Health Monitor service '{service}' is not installed/loaded; no panel API operation was attempted"
            )
        active = subprocess.run(
            [systemctl, "is-active", "--quiet", service],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise IntegrationError("Could not verify the DoH Health Monitor systemd service") from None
    if active.returncode != 0:
        raise IntegrationError(
            f"DoH Health Monitor service '{service}' is installed but not active; no panel API operation was attempted"
        )
    print(f"PASS: DoH Health Monitor service '{service}' is installed and active")

    for proto, flag in (("TCP", "-ltn"), ("UDP", "-lun")):
        try:
            result = subprocess.run(
                [ss, "-H", *flag.split()],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise IntegrationError(f"Could not inspect the DoH listener ({proto})") from None
        if result.returncode != 0 or not listener_output_has_loopback_port(result.stdout or "", port):
            raise IntegrationError(
                f"DoH Health Monitor loopback listener {port}/{proto} is not active; no panel API operation was attempted"
            )
        print(f"PASS: DoH Health Monitor loopback listener {port}/{proto} is active")

    request = Request(status_url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=3) as response:
            body = response.read(1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise IntegrationError(
            "DoH Health Monitor status API is unavailable; no panel API operation was attempted"
        ) from None
    validate_plugin_status(body)
    print("PASS: DoH Health Monitor status API returns a JSON object")


def read_tty_confirmation(prompt: str) -> str:
    """Read from /dev/tty even when Python receives its source through a pipe."""
    try:
        # A TTY is not seekable, so Python's buffered "r+" mode rejects it.
        # Use separate write/read streams for the same controlling terminal.
        with open("/dev/tty", "w", encoding="utf-8") as tty_out:
            tty_out.write(prompt)
            tty_out.flush()
        with open("/dev/tty", "r", encoding="utf-8") as tty_in:
            return tty_in.readline().strip()
    except OSError:
        raise IntegrationError("Interactive confirmation requires a controlling TTY") from None


def panel_api_is_local(base_url: str) -> bool:
    parsed = urlsplit(base_url)
    if not parsed.hostname:
        return False
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return parsed.hostname.lower() == "localhost"


def check_xray_compatibility(explicit_binary: str | None = None) -> str | None:
    """Report local versions for diagnostics; API/config validation is the compatibility gate."""
    panel_version = detect_panel_version()
    print("LucX-UI version:", panel_version or "not detected (informational only)")
    try:
        binary = find_xray_binary(explicit_binary)
        version = read_xray_version(binary)
    except IntegrationError as exc:
        print("WARNING: Xray version could not be detected; continuing with API-based checks.")
        print("Version diagnostic:", str(exc))
        return None

    print("Detected Xray core:", version)
    if xray_version_is_verified(version):
        print("Xray version: present in the informational verified-version list.")
    else:
        print("NOTICE: Xray version is not in the informational verified-version list.")
    print("Xray version does not block check/plan; compatibility is assessed through panel API")
    print("response parsing, configuration validation, conflict detection, and read-back.")
    return version


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def object_list(parent: dict, key: str, description: str) -> list[dict]:
    if key not in parent:
        parent[key] = []
    value = parent[key]
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise IntegrationError(f"Invalid {description}: expected an array of objects")
    return value


def _as_tokens(value: object) -> set[str]:
    if isinstance(value, str):
        return {x.strip().lower() for x in value.split(",") if x.strip()}
    if isinstance(value, list):
        return {str(x).strip().lower() for x in value if str(x).strip()}
    return set()


def _port_contains(value: object, wanted: int) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == wanted
    if not isinstance(value, str):
        return False
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            try:
                if int(left) <= wanted <= int(right):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == wanted:
                    return True
            except ValueError:
                continue
    return False


def _ip_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


def _is_api_rule(rule: dict) -> bool:
    if rule.get("outboundTag") != "api":
        return False
    return "api" in _as_tokens(rule.get("inboundTag"))


def _global_port53_rule(rule: dict) -> bool:
    port = rule.get("port")
    if rule.get("enabled") is False:
        return False
    if isinstance(port, bool):
        return False
    if isinstance(port, int):
        if port != 53:
            return False
    elif isinstance(port, str):
        if port.strip() != "53":
            return False
    else:
        return False

    networks = _as_tokens(rule.get("network"))
    if networks and networks != {"tcp", "udp"}:
        return False
    # Any inboundTag, domain, IP, protocol, source, or balancer selector
    # would narrow/alter the intended all-tunnel TCP+UDP interception.
    allowed = {
        "type", "ruleTag", "enabled", "network", "port",
        "outboundTag", "balancerTag", "remarks", "comment",
    }
    if any(key not in allowed for key in rule):
        return False
    has_outbound = isinstance(rule.get("outboundTag"), str) and bool(rule.get("outboundTag"))
    has_balancer = isinstance(rule.get("balancerTag"), str) and bool(rule.get("balancerTag"))
    # Xray uses outboundTag when both target fields are supplied.
    return rule.get("type", "field") == "field" and (has_outbound or has_balancer)


def _split_ip_address(address: str, explicit_port: object = None) -> tuple[str, int] | None:
    address = address.strip()
    if not address:
        return None

    scheme = ""
    if "://" in address:
        scheme, address = address.split("://", 1)
        address = address.split("/", 1)[0]
    else:
        address = address.split("/", 1)[0]

    remote_doh = scheme.lower() in {"https", "h2c"}
    port = 443 if remote_doh else 53
    host = address

    if address.startswith("[") and "]" in address:
        end = address.index("]")
        host = address[1:end]
        suffix = address[end + 1:]
        if suffix.startswith(":") and suffix[1:].isdigit():
            port = int(suffix[1:])
    elif address.count(":") == 1:
        candidate_host, candidate_port = address.rsplit(":", 1)
        if candidate_port.isdigit():
            host, port = candidate_host, int(candidate_port)

    if explicit_port is not None and not remote_doh:
        try:
            parsed_port = int(explicit_port)
            if parsed_port > 0:
                port = parsed_port
        except (TypeError, ValueError):
            pass

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(ip), port


def _is_blocked_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    private_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    ]
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if any(ip.version == network.version and ip in network for network in private_networks):
        return True
    extra = [
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("2002::/16"),
        ipaddress.ip_network("2001::/32"),
        ipaddress.ip_network("64:ff9b:1::/48"),
        ipaddress.ip_network("fec0::/10"),
    ]
    if any(ip.version == network.version and ip in network for network in extra):
        return True
    nat64 = ipaddress.ip_network("64:ff9b::/96")
    if ip.version == 6 and ip in nat64:
        embedded = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        return _is_blocked_ip(str(embedded))
    return False


def _dns_private_groups(config: dict) -> list[tuple[int, list[str]]]:
    dns = config.get("dns", {})
    if not isinstance(dns, dict):
        return []
    servers = dns.get("servers", [])
    if not isinstance(servers, list):
        return []
    grouped: dict[int, set[str]] = {}
    for entry in servers:
        address = ""
        explicit_port = None
        if isinstance(entry, str):
            address = entry
        elif isinstance(entry, dict):
            address = entry.get("address", "") if isinstance(entry.get("address", ""), str) else ""
            explicit_port = entry.get("port")
        endpoint = _split_ip_address(address, explicit_port)
        if endpoint is None:
            continue
        ip, port = endpoint
        if _is_blocked_ip(ip):
            grouped.setdefault(port, set()).add(ip)
    return [(port, sorted(grouped[port])) for port in sorted(grouped)]


def _legacy_managed_dns_allow(rule: dict, groups: list[tuple[int, list[str]]]) -> bool:
    if rule.get("type") != "field" or rule.get("outboundTag") != "direct":
        return False
    if "ip" not in rule or "port" not in rule:
        return False
    for key, value in rule.items():
        if key in {"type", "outboundTag", "ip", "port"}:
            continue
        if key == "enabled" and value is True:
            continue
        return False
    port = rule.get("port")
    ips = sorted(_ip_values(rule.get("ip")))
    return any(str(group_port) == str(port) and group_ips == ips for group_port, group_ips in groups)


def panel_normalize_dns_allow_rules(config: dict) -> dict:
    """Model LucX-UI EnsureDnsServerRouting for safe before/after verification."""
    result = copy.deepcopy(config)
    routing = result.get("routing")
    if not isinstance(routing, dict):
        return result
    rules = routing.get("rules", [])
    if not isinstance(rules, list) or any(not isinstance(x, dict) for x in rules):
        raise IntegrationError("Invalid routing.rules; cannot predict panel normalization")

    groups = _dns_private_groups(result)
    clean = []
    for rule in rules:
        if rule.get("ruleTag") == DNS_ALLOW_TAG:
            continue
        if _legacy_managed_dns_allow(rule, groups):
            continue
        clean.append(copy.deepcopy(rule))

    private_block = next(
        (
            i for i, rule in enumerate(clean)
            if rule.get("outboundTag") == "blocked"
            and any(x.lower() == "geoip:private" for x in _ip_values(rule.get("ip")))
        ),
        -1,
    )
    if private_block >= 0 and groups:
        managed = [
            {
                "type": "field",
                "ruleTag": DNS_ALLOW_TAG,
                "ip": ips,
                "port": str(port),
                "outboundTag": "direct",
            }
            for port, ips in groups
        ]
        clean[private_block:private_block] = managed
    routing["rules"] = clean
    result["routing"] = routing
    return result


def _has_numeric_qtype_zero(config: dict) -> bool:
    outbounds = config.get("outbounds", [])
    if not isinstance(outbounds, list):
        return False
    for outbound in outbounds:
        if not isinstance(outbound, dict) or str(outbound.get("protocol", "")).lower() != "dns":
            continue
        settings = outbound.get("settings", {})
        if not isinstance(settings, dict):
            continue
        dns_rules = settings.get("rules", [])
        if not isinstance(dns_rules, list):
            continue
        for rule in dns_rules:
            if isinstance(rule, dict):
                value = rule.get("qType")
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0:
                    return True
    return False


@dataclass
class Plan:
    proposed: dict
    expected_saved: dict
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)


def _direct_freedom_outbound(config: dict) -> dict:
    outbounds = object_list(config, "outbounds", "outbounds")
    matches = [
        item for item in outbounds
        if item.get("tag") == "direct" and item.get("protocol") == "freedom"
    ]
    all_direct = [item for item in outbounds if item.get("tag") == "direct"]
    if len(matches) != 1 or len(all_direct) != 1:
        raise IntegrationError(
            "Temporary DNS finalRule requires exactly one direct freedom outbound"
        )
    settings = matches[0].get("settings")
    if settings is None:
        settings = {}
        matches[0]["settings"] = settings
    if not isinstance(settings, dict):
        raise IntegrationError("direct outbound settings must be an object")
    return matches[0]


def _remove_persistent_temporary_dns_rule(config: dict) -> bool:
    """Remove only the exact manually-installed rule now owned by the self-test."""
    direct = _direct_freedom_outbound(config)
    settings = direct["settings"]
    rules = settings.get("finalRules", [])
    if not isinstance(rules, list) or any(not isinstance(item, dict) for item in rules):
        raise IntegrationError("direct.settings.finalRules must be an array of objects")
    matches = [i for i, item in enumerate(rules) if canonical(item) == canonical(TEMP_DNS_FINAL_RULE)]
    if len(matches) > 1:
        raise IntegrationError("Duplicate temporary DNS finalRules exist; refusing automatic cleanup")
    if matches:
        del rules[matches[0]]
        if rules:
            settings["finalRules"] = rules
        else:
            settings.pop("finalRules", None)
        return True
    return False


def build_plan(original: dict, *, require_api_rule: bool = True) -> Plan:
    """Build the panel-aware plan from the shared semantic Xray inventory."""
    if not isinstance(original, dict):
        raise IntegrationError("xraySetting must be a JSON object")

    cfg = copy.deepcopy(original)
    plan = Plan(proposed=cfg, expected_saved={})

    # Check panel serialization hazards before semantic planning can return
    # early on an unrelated DNS-routing incompatibility.
    if _has_numeric_qtype_zero(original):
        plan.blockers.append(
            "Panel save would rewrite an existing numeric DNS qType 0 to string '0'; refusing to change an unrelated DNS setting"
        )
        return plan

    # A manually-persisted copy of the reserved self-test finalRule is not a
    # permanent integration object. Transfer it to the temporary test lifecycle.
    direct_matches = [
        item for item in cfg.get("outbounds", [])
        if isinstance(item, dict) and item.get("tag") == "direct"
    ] if isinstance(cfg.get("outbounds", []), list) else []
    if any(
        isinstance(item.get("settings"), dict)
        and isinstance(item["settings"].get("finalRules", []), list)
        and any(
            isinstance(rule, dict) and canonical(rule) == canonical(TEMP_DNS_FINAL_RULE)
            for rule in item["settings"].get("finalRules", [])
        )
        for item in direct_matches
    ):
        try:
            if _remove_persistent_temporary_dns_rule(cfg):
                plan.changes.append(
                    "REMOVE manually-persisted temporary DNS allow finalRule; it will exist only during the Tunnel self-test"
                )
        except IntegrationError as exc:
            plan.blockers.append(str(exc))
            return plan

    try:
        semantic = build_dns_plan(cfg)
    except (ValueError, TypeError) as exc:
        plan.blockers.append(f"Xray DNS inventory failed: {exc}")
        return plan

    plan.proposed = semantic.proposed
    plan.changes.extend(semantic.changes)
    plan.warnings.extend(semantic.warnings)
    plan.blockers.extend(semantic.blockers)
    if plan.blockers:
        return plan

    proposed = plan.proposed
    outbounds = object_list(proposed, "outbounds", "outbounds")
    routing = proposed.get("routing")
    if not isinstance(routing, dict):
        plan.blockers.append("routing is not an object")
        return plan
    rules = object_list(routing, "rules", "routing.rules")

    api_indexes = [i for i, rule in enumerate(rules) if _is_api_rule(rule)]
    if require_api_rule and (len(api_indexes) != 1 or api_indexes[0] != 0):
        plan.blockers.append(
            "LucX-UI requires its api-inbound -> api-outbound rule at routing.rules[0]; the panel would add or move it during save"
        )

    # Verify the panel's DNS synchronization does not rewrite existing rules.
    try:
        after_normalized = panel_normalize_dns_allow_rules(proposed)
        before_rules = (
            original.get("routing", {}).get("rules", [])
            if isinstance(original.get("routing"), dict) else []
        )
        after_before_rules = (
            after_normalized.get("routing", {}).get("rules", [])
            if isinstance(after_normalized.get("routing"), dict) else []
        )
        cursor = 0
        for old_rule in before_rules:
            while (
                cursor < len(after_before_rules)
                and canonical(after_before_rules[cursor]) != canonical(old_rule)
            ):
                cursor += 1
            if cursor >= len(after_before_rules):
                plan.blockers.append(
                    "Panel DNS synchronization would rewrite or remove an existing routing rule; manual review required"
                )
                break
            cursor += 1
    except IntegrationError as exc:
        plan.blockers.append(str(exc))

    # LucX-UI owns the private-DNS allow exception. Verify its required
    # direct outbound, but never create, rename, or move the managed rule here.
    private_block_exists = any(
        rule.get("outboundTag") == "blocked"
        and any(value.lower() == "geoip:private" for value in _ip_values(rule.get("ip")))
        for rule in rules
    )
    if private_block_exists:
        direct_matches = [item for item in outbounds if item.get("tag") == "direct"]
        if len(direct_matches) != 1:
            plan.blockers.append(
                "A private-IP block exists, but there is not exactly one direct outbound for the panel-managed DNS exception"
            )

    try:
        plan.expected_saved = panel_normalize_dns_allow_rules(proposed)
        if canonical(plan.expected_saved) != canonical(proposed):
            plan.changes.append(
                "PANEL-MANAGED: LucX-UI will add/reconcile its xui-dns-allow exception for private DNS servers"
            )
        expected_rules = plan.expected_saved.get("routing", {}).get("rules", [])
        if private_block_exists:
            managed = [
                rule for rule in expected_rules
                if rule.get("ruleTag") == DNS_ALLOW_TAG
                and str(rule.get("port")) == "5355"
                and "127.0.0.1" in _ip_values(rule.get("ip"))
            ]
            if not managed:
                plan.blockers.append(
                    "Panel normalization did not produce the expected xui-dns-allow rule for 127.0.0.1:5355"
                )
            else:
                plan.warnings.append(
                    "LucX-UI manages xui-dns-allow for 127.0.0.1:5355 before geoip:private; the adapter will not write this rule itself"
                )
    except IntegrationError as exc:
        plan.blockers.append(str(exc))

    return plan


def _is_subsequence(old: list, new: list) -> bool:
    cursor = 0
    for item in new:
        if cursor < len(old) and canonical(old[cursor]) == canonical(item):
            cursor += 1
    return cursor == len(old)


def parse_api_response(body: bytes) -> dict:
    try:
        envelope = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("Panel API returned invalid JSON") from None
    if not isinstance(envelope, dict) or envelope.get("success") is not True:
        raise IntegrationError("Panel API reported an unsuccessful request")
    return envelope


class PanelAPI:
    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 15.0,
        allow_insecure_http: bool = False,
        host_header: str | None = None,
        tls_server_name: str | None = None,
        tls_verify_ip: str | None = None,
    ):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise IntegrationError("--base-url must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise IntegrationError("--base-url must not contain credentials, query, or fragment")
        if parsed.scheme == "http" and not allow_insecure_http:
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = parsed.hostname in {"localhost"}
            if not loopback:
                raise IntegrationError("Plain HTTP is refused for non-loopback hosts; use HTTPS or --allow-insecure-http")
        self.root = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
        self.token = token
        self.timeout = timeout
        self.host_header = host_header
        self.opener = build_opener(
            _PanelSNIHTTPSHandler(tls_server_name, verify_ip=tls_verify_ip)
        ) if (parsed.scheme == "https" and (tls_server_name or tls_verify_ip)) else None

    def _post(self, suffix: str, fields: dict[str, str] | None = None) -> dict:
        url = self.root + "/panel/api/xray/" + suffix
        data = urlencode(fields or {}).encode("utf-8")
        request = Request(
            url,
            data=data,
            method="POST",
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "lucx-ui-doh-api/" + VERSION,
                **({"Host": self.host_header} if self.host_header else {}),
            },
        )
        try:
            response_context = (
                self.opener.open(request, timeout=self.timeout)
                if self.opener
                else urlopen(request, timeout=self.timeout)
            )
            with response_context as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise IntegrationError(f"Panel API HTTP error ({exc.code}); response body suppressed") from None
        except (URLError, TimeoutError, OSError):
            raise IntegrationError("Could not reach the panel API; network details suppressed") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise IntegrationError("Panel API response exceeded the size limit")
        return parse_api_response(body)

    def get_snapshot(self) -> dict:
        envelope = self._post("")
        payload = envelope.get("obj")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                raise IntegrationError("Panel returned an invalid xray settings payload") from None
        if not isinstance(payload, dict):
            raise IntegrationError("Panel response does not contain the xray settings object")
        raw_config = payload.get("xraySetting")
        if isinstance(raw_config, str):
            try:
                raw_config = json.loads(raw_config)
            except json.JSONDecodeError:
                raise IntegrationError("Panel returned invalid xraySetting JSON") from None
        if not isinstance(raw_config, dict):
            raise IntegrationError("Panel response does not contain an xraySetting object")
        test_url = payload.get("outboundTestUrl")
        if not isinstance(test_url, str) or not test_url.strip():
            raise IntegrationError("Panel did not return outboundTestUrl; refusing to overwrite panel metadata")
        return {"xraySetting": raw_config, "outboundTestUrl": test_url}

    def update(self, config: dict, outbound_test_url: str) -> None:
        fields = {
            "xraySetting": json.dumps(config, ensure_ascii=False, separators=(",", ":")),
            "outboundTestUrl": outbound_test_url,
        }
        self._post("update", fields)

    def _inbound_request(self, method: str, suffix: str, payload: dict | None = None) -> dict:
        """Call the official LucX-UI inbound API; never expose response bodies on errors."""
        url = self.root + "/panel/api/inbounds/" + suffix.lstrip("/")
        data = None if payload is None else json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        request = Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "User-Agent": "lucx-ui-doh-api/" + VERSION,
                **({"Content-Type": "application/json"} if data is not None else {}),
                **({"Host": self.host_header} if self.host_header else {}),
            },
        )
        try:
            response_context = (
                self.opener.open(request, timeout=self.timeout)
                if self.opener else urlopen(request, timeout=self.timeout)
            )
            with response_context as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise IntegrationError(
                f"LucX-UI inbound API HTTP error ({exc.code}); response body suppressed"
            ) from None
        except (URLError, TimeoutError, OSError):
            raise IntegrationError(
                "Could not reach the LucX-UI inbound API; network details suppressed"
            ) from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise IntegrationError("LucX-UI inbound API response exceeded the size limit")
        return parse_api_response(body)

    @staticmethod
    def _inbound_object(envelope: dict, description: str) -> dict:
        value = envelope.get("obj")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise IntegrationError(f"LucX-UI returned invalid {description} JSON") from None
        if not isinstance(value, dict):
            raise IntegrationError(f"LucX-UI response does not contain {description}")
        return value

    def list_inbounds(self) -> list[dict]:
        envelope = self._inbound_request("GET", "list")
        value = envelope.get("obj")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise IntegrationError("LucX-UI returned an invalid inbound list") from None
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise IntegrationError("LucX-UI response does not contain an inbound list")
        return value

    def add_inbound(self, inbound: dict) -> dict:
        if not isinstance(inbound, dict) or inbound.get("protocol") != "tunnel":
            raise IntegrationError("Only a Tunnel inbound can be created by this integration")
        envelope = self._inbound_request("POST", "add", inbound)
        created = self._inbound_object(envelope, "created inbound")
        if isinstance(created.get("id"), bool) or not isinstance(created.get("id"), int) or created["id"] <= 0:
            raise IntegrationError("LucX-UI did not return a valid ID for the created Tunnel inbound")
        return created

    def delete_inbound(self, inbound_id: int) -> None:
        if isinstance(inbound_id, bool) or not isinstance(inbound_id, int) or inbound_id <= 0:
            raise IntegrationError("Refusing to delete an inbound without a valid numeric ID")
        self._inbound_request("POST", f"del/{inbound_id}")




TUNNEL_PORT_CANDIDATES = tuple(range(15353, 15454))
TUNNEL_REMARK_PREFIX = "doh-health-monitor-selftest-"


def _port_is_free_on_loopback(port: int) -> bool:
    """Require both TCP and UDP loopback binds to succeed; this is preflight only."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise IntegrationError("Invalid temporary Tunnel port")
    sockets = []
    try:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            probe = socket.socket(socket.AF_INET, kind)
            sockets.append(probe)
            probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        for probe in sockets:
            probe.close()


def choose_temporary_tunnel_port(inbounds: list[dict], candidates=TUNNEL_PORT_CANDIDATES) -> int:
    """Choose a free loopback port not reserved by any panel inbound."""
    if not isinstance(inbounds, list):
        raise IntegrationError("Cannot choose a test port without a valid inbound list")
    reserved = set()
    for item in inbounds:
        if not isinstance(item, dict):
            raise IntegrationError("Panel returned an invalid inbound entry")
        port = item.get("port")
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            listen = str(item.get("listen") or "").strip().lower()
            if listen in {"", "0.0.0.0", "::", "[::]", "127.0.0.1", "::1", "[::1]"}:
                reserved.add(port)
    for candidate in candidates:
        if candidate not in reserved and _port_is_free_on_loopback(candidate):
            return candidate
    raise IntegrationError("No free loopback TCP+UDP port is available for the temporary Tunnel test")


def build_temporary_tunnel(port: int, run_id: str | None = None) -> dict:
    """Build a loopback-only Tunnel that forwards DNS to the plugin's local resolver."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise IntegrationError("Invalid temporary Tunnel port")
    marker = run_id or secrets.token_hex(8)
    if not re.fullmatch(r"[a-f0-9]{8,32}", marker):
        raise IntegrationError("Invalid temporary Tunnel run marker")
    return {
        "remark": TUNNEL_REMARK_PREFIX + marker,
        "protocol": "tunnel",
        "listen": "127.0.0.1",
        "port": port,
        "settings": json.dumps({
            "rewriteAddress": "127.0.0.1",
            "rewritePort": 53,
            "allowedNetwork": "tcp,udp",
            "followRedirect": False,
            "portMap": {},
        }, separators=(",", ":")),
        "enable": True,
    }


def verify_temporary_tunnel(inbounds: list[dict], expected: dict, inbound_id: int) -> dict:
    """Verify the exact created object by ID and immutable identity fields."""
    matches = [
        item for item in inbounds
        if isinstance(item, dict)
        and not isinstance(item.get("id"), bool)
        and item.get("id") == inbound_id
    ]
    if len(matches) != 1:
        raise IntegrationError("Created temporary Tunnel cannot be uniquely identified in the panel")
    actual = matches[0]
    for key in ("remark", "protocol", "listen", "port"):
        if actual.get(key) != expected.get(key):
            raise IntegrationError("Temporary Tunnel identity changed; refusing to modify or delete it")
    try:
        settings = actual.get("settings")
        if isinstance(settings, str):
            settings = json.loads(settings)
    except json.JSONDecodeError:
        settings = None
    if not isinstance(settings, dict) or (
        settings.get("rewriteAddress") != "127.0.0.1"
        or settings.get("rewritePort") != 53
        or settings.get("allowedNetwork") != "tcp,udp"
        or settings.get("followRedirect") is not False
        or settings.get("portMap") != {}
    ):
        raise IntegrationError("Temporary Tunnel settings do not match the expected DNS test target")
    return actual


def cleanup_temporary_tunnel(client: PanelAPI, expected: dict, inbound_id: int | None) -> bool:
    """Delete only this run's inbound after identity read-back, then verify absence."""
    current = client.list_inbounds()
    if inbound_id is None:
        matches = [
            item for item in current
            if isinstance(item, dict) and item.get("remark") == expected.get("remark")
        ]
        if len(matches) > 1:
            raise IntegrationError("Multiple inbounds match the temporary Tunnel recovery marker; refusing deletion")
        if not matches:
            return False
        inbound_id = matches[0].get("id")
        if isinstance(inbound_id, bool) or not isinstance(inbound_id, int) or inbound_id <= 0:
            raise IntegrationError("Temporary Tunnel recovery match has no valid numeric ID")
    matches = [
        item for item in current
        if isinstance(item, dict)
        and not isinstance(item.get("id"), bool)
        and item.get("id") == inbound_id
    ]
    if not matches:
        if any(
            isinstance(item, dict) and item.get("remark") == expected.get("remark")
            for item in current
        ):
            raise IntegrationError(
                "Temporary Tunnel recovery marker exists under a different ID; refusing deletion"
            )
        return False
    verify_temporary_tunnel(current, expected, inbound_id)
    client.delete_inbound(inbound_id)
    remaining = client.list_inbounds()
    if any(isinstance(item, dict) and item.get("id") == inbound_id for item in remaining):
        raise IntegrationError(
            f"Temporary Tunnel cleanup could not be verified; recovery required for inbound ID {inbound_id}"
        )
    return True


def wait_for_tunnel_listeners(port: int, timeout: float = 20.0) -> None:
    """Wait for LucX-UI/Xray to expose both TCP and UDP loopback listeners."""
    ss = shutil.which("ss")
    if not ss:
        raise IntegrationError("The ss utility is required to verify temporary Tunnel listeners")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = {}
        for proto, flag in (("tcp", "-ltn"), ("udp", "-lun")):
            result = subprocess.run(
                [ss, "-H", *flag.split()],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                raise IntegrationError("Could not inspect temporary Tunnel listeners")
            observed[proto] = listener_output_has_loopback_port(result.stdout or "", port)
        if observed["tcp"] and observed["udp"]:
            return
        time.sleep(0.25)
    raise IntegrationError(
        f"Temporary Tunnel listeners did not become active on loopback port {port} (TCP and UDP)"
    )


def _write_recovery_journal(
    backup_dir: Path, expected: dict, inbound_id: int | None, state: str,
    *, final_rule: dict | None = None,
) -> Path:
    marker = expected["remark"].removeprefix(TUNNEL_REMARK_PREFIX)
    journal_dir = backup_dir / "recovery"
    journal_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(journal_dir, 0o700)
    path = journal_dir / f"lucx-doh-selftest-{marker}.json"
    _write_private_json(path, {
        "format": 1,
        "kind": "temporary-tunnel-selftest",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "state": state,
        "inbound_id": inbound_id,
        "inbound": expected,
        "final_rule": copy.deepcopy(final_rule or TEMP_DNS_FINAL_RULE),
    })
    return path


def _load_recovery_journal(path: Path) -> dict:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise IntegrationError("Recovery journal must be a private regular file owned by the current user with mode 0600")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except IntegrationError:
        raise
    except (OSError, json.JSONDecodeError):
        raise IntegrationError("Cannot read the temporary Tunnel recovery journal") from None
    inbound = payload.get("inbound") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict) or payload.get("format") != 1
        or payload.get("kind") != "temporary-tunnel-selftest"
        or not isinstance(inbound, dict)
        or inbound.get("protocol") != "tunnel"
        or not str(inbound.get("remark", "")).startswith(TUNNEL_REMARK_PREFIX)
        or inbound.get("listen") != "127.0.0.1"
        or isinstance(inbound.get("port"), bool)
        or not isinstance(inbound.get("port"), int)
        or not 1 <= inbound["port"] <= 65535
    ):
        raise IntegrationError("Recovery journal format or temporary Tunnel identity is invalid")
    inbound_id = payload.get("inbound_id")
    if inbound_id is not None and (
        isinstance(inbound_id, bool) or not isinstance(inbound_id, int) or inbound_id <= 0
    ):
        raise IntegrationError("Recovery journal contains an invalid inbound ID")
    final_rule = payload.get("final_rule")
    if final_rule is not None and (
        not isinstance(final_rule, dict)
        or canonical(final_rule) != canonical(TEMP_DNS_FINAL_RULE)
    ):
        raise IntegrationError("Recovery journal temporary DNS finalRule identity is invalid")
    return payload


def listener_output_has_port(output: str, port: int) -> bool:
    """Detect a listening socket on the port regardless of its bind address."""
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].endswith(f":{port}"):
            return True
    return False


def wait_for_tunnel_port_closed(port: int, timeout: float = 10.0) -> None:
    """Verify that both TCP and UDP listeners disappeared after panel API deletion."""
    ss = shutil.which("ss")
    if not ss:
        raise IntegrationError("The ss utility is required to verify temporary Tunnel cleanup")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        states = []
        for flag in ("-ltn", "-lun"):
            result = subprocess.run(
                [ss, "-H", *flag.split()],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                raise IntegrationError("Could not verify temporary Tunnel port release")
            states.append(listener_output_has_port(result.stdout or "", port))
        if not any(states):
            return
        time.sleep(0.25)
    raise IntegrationError(
        f"Temporary Tunnel inbound was deleted but a TCP/UDP listener remains on port {port}"
    )


def find_pending_recovery_journals(backup_dir: Path) -> list[Path]:
    recovery_dir = backup_dir / "recovery"
    try:
        info = recovery_dir.lstat()
    except FileNotFoundError:
        return []
    except OSError:
        raise IntegrationError("Could not inspect the temporary Tunnel recovery directory") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise IntegrationError("Temporary Tunnel recovery directory must be a private directory owned by the current user with mode 0700")
    journals = sorted(recovery_dir.glob("lucx-doh-selftest-*.json"))
    for journal in journals:
        _load_recovery_journal(journal)
    return journals


def install_temporary_dns_final_rule(
    client: PanelAPI, *, attempt_state: list[bool] | None = None
) -> None:
    """Install the reserved loopback finalRule and report when the API write is attempted."""
    before = client.get_snapshot()
    config = copy.deepcopy(before["xraySetting"])
    direct = _direct_freedom_outbound(config)
    settings = direct["settings"]
    rules = settings.get("finalRules", [])
    if not isinstance(rules, list) or any(not isinstance(item, dict) for item in rules):
        raise IntegrationError("direct.settings.finalRules must be an array of objects")
    if any(canonical(item) == canonical(TEMP_DNS_FINAL_RULE) for item in rules):
        raise IntegrationError(
            "Temporary DNS finalRule is already present after permanent-config normalization; refusing to claim ownership"
        )
    rules.append(copy.deepcopy(TEMP_DNS_FINAL_RULE))
    settings["finalRules"] = rules
    # Mark ownership only after the existing-rule guard, immediately before
    # the API write. If the API response is lost after commit, finally cleanup
    # must still run; if the guard refused an existing entry, it must not.
    if attempt_state is not None:
        attempt_state[0] = True
    client.update(config, before["outboundTestUrl"])
    after = client.get_snapshot()
    after_direct = _direct_freedom_outbound(after["xraySetting"])
    after_rules = after_direct["settings"].get("finalRules", [])
    if not isinstance(after_rules, list) or sum(
        1 for item in after_rules
        if isinstance(item, dict) and canonical(item) == canonical(TEMP_DNS_FINAL_RULE)
    ) != 1:
        raise IntegrationError("Panel read-back did not confirm the temporary DNS finalRule")


def cleanup_temporary_dns_final_rule(client: PanelAPI, final_rule: dict) -> bool:
    """Remove only this run's exact allow finalRule, preserving all current unrelated settings."""
    if canonical(final_rule) != canonical(TEMP_DNS_FINAL_RULE):
        raise IntegrationError("Refusing to remove an unrecognized temporary DNS finalRule")
    current = client.get_snapshot()
    config = copy.deepcopy(current["xraySetting"])
    direct = _direct_freedom_outbound(config)
    settings = direct["settings"]
    rules = settings.get("finalRules", [])
    if not isinstance(rules, list) or any(not isinstance(item, dict) for item in rules):
        raise IntegrationError("direct.settings.finalRules is not a valid array; recovery required")
    matches = [i for i, item in enumerate(rules) if canonical(item) == canonical(final_rule)]
    if not matches:
        return False
    # Every exact match is the reserved self-test object. Remove all such
    # leftovers while preserving every non-matching user finalRule.
    for index in reversed(matches):
        del rules[index]
    if rules:
        settings["finalRules"] = rules
    else:
        settings.pop("finalRules", None)
    client.update(config, current["outboundTestUrl"])
    restored = client.get_snapshot()
    restored_direct = _direct_freedom_outbound(restored["xraySetting"])
    restored_rules = restored_direct["settings"].get("finalRules", [])
    if not isinstance(restored_rules, list) or any(
        isinstance(item, dict) and canonical(item) == canonical(final_rule)
        for item in restored_rules
    ):
        raise IntegrationError("Panel read-back could not verify temporary DNS finalRule removal")
    return True


def run_temporary_tunnel_test(client: PanelAPI, status_url: str, backup_dir: Path) -> None:
    """Create, verify, probe, and always clean up one temporary loopback DNS Tunnel."""
    remaining = list(TUNNEL_PORT_CANDIDATES)
    for attempt in range(3):
        inbounds = client.list_inbounds()
        port = choose_temporary_tunnel_port(inbounds, candidates=remaining)
        remaining.remove(port)
        expected = build_temporary_tunnel(port)
        journal = _write_recovery_journal(
            backup_dir, expected, None, "create-pending", final_rule=TEMP_DNS_FINAL_RULE
        )
        inbound_id = None
        test_error = None
        cleanup_error = None
        add_error = None
        final_rule_attempted = [False]
        try:
            journal = _write_recovery_journal(
                backup_dir, expected, None, "final-rule-create-pending",
                final_rule=TEMP_DNS_FINAL_RULE,
            )
            install_temporary_dns_final_rule(
                client, attempt_state=final_rule_attempted
            )
            journal = _write_recovery_journal(
                backup_dir, expected, None, "final-rule-created",
                final_rule=TEMP_DNS_FINAL_RULE,
            )
            try:
                created = client.add_inbound(expected)
            except IntegrationError as exc:
                add_error = exc
                raise
            inbound_id = created["id"]
            journal = _write_recovery_journal(backup_dir, expected, inbound_id, "created")
            current = client.list_inbounds()
            verify_temporary_tunnel(current, expected, inbound_id)
            wait_for_tunnel_listeners(port)
            # The permanent port-53 -> dns-out rule routes the Tunnel's rewritten
            # 127.0.0.1:53 destination to the plugin. No temporary Xray routing
            # mutation or second Xray restart is necessary.
            run_tunnel_dns_self_test(port, status_url)
        except Exception as exc:
            test_error = exc
        finally:
            cleanup_errors = []
            try:
                removed = cleanup_temporary_tunnel(client, expected, inbound_id)
                # If the add request failed and no matching panel object exists,
                # a listener may belong to the process that won the port race.
                # Never wait for or interfere with that external listener.
                if inbound_id is not None or removed:
                    wait_for_tunnel_port_closed(port)
            except Exception as exc:
                cleanup_errors.append("Tunnel: " + str(exc))

            # Cleanup is deliberately independent: a failed inbound deletion
            # must not prevent an attempt to remove the temporary finalRule.
            if final_rule_attempted[0]:
                try:
                    cleanup_temporary_dns_final_rule(client, TEMP_DNS_FINAL_RULE)
                except Exception as exc:
                    cleanup_errors.append("finalRule: " + str(exc))

            if cleanup_errors:
                cleanup_error = IntegrationError("; ".join(cleanup_errors))
                try:
                    _write_recovery_journal(
                        backup_dir, expected, inbound_id, "cleanup-required",
                        final_rule=TEMP_DNS_FINAL_RULE,
                    )
                except Exception:
                    pass
            else:
                journal.unlink(missing_ok=True)
        if cleanup_error:
            raise IntegrationError(
                f"Temporary Tunnel/finalRule cleanup failed; recovery journal retained at {journal}. "
                f"Resource marker: {expected['remark']}; inbound ID: {inbound_id or 'unknown'}; "
                f"details: {cleanup_error}"
            ) from None
        if test_error:
            if add_error is not None and not _port_is_free_on_loopback(port) and attempt < 2:
                print(f"NOTICE: port {port} was claimed during Tunnel creation; retrying with another free port.")
                continue
            if isinstance(test_error, IntegrationError):
                raise test_error
            raise IntegrationError(
                "Temporary Tunnel self-test failed; temporary inbound was cleaned up. "
                f"Underlying error: {_safe_exception_summary(test_error)}"
            ) from None
        print("PASS: temporary Tunnel inbound was removed and panel API read-back confirms absence.")
        print(f"PASS: temporary Tunnel TCP and UDP listeners are gone from port {port}.")
        return
    raise IntegrationError("Temporary Tunnel creation repeatedly lost a port-allocation race")




def _dns_query_packet(name: str) -> tuple[int, bytes]:
    if not isinstance(name, str) or not name or len(name) > 253:
        raise IntegrationError("Invalid DNS self-test hostname")
    query_id = secrets.randbelow(65536)
    labels = name.rstrip(".").split(".")
    if any(not label or len(label.encode("idna")) > 63 for label in labels):
        raise IntegrationError("Invalid DNS self-test hostname")
    qname = b"".join(bytes([len(label.encode("idna"))]) + label.encode("idna") for label in labels) + b"\0"
    return query_id, struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def _skip_dns_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise IntegrationError("DNS response contains a truncated name")
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise IntegrationError("DNS response contains a truncated compression pointer")
            return offset + 2
        if size & 0xC0:
            raise IntegrationError("DNS response contains an invalid label encoding")
        offset += 1
        if size == 0:
            return offset
        if size > 63 or offset + size > len(packet):
            raise IntegrationError("DNS response contains an invalid label length")
        offset += size


def _parse_dns_a_response(packet: bytes, expected_id: int) -> list[str]:
    if len(packet) < 12:
        raise IntegrationError("DNS self-test response is shorter than a DNS header")
    query_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if query_id != expected_id or not (flags & 0x8000):
        raise IntegrationError("DNS self-test response does not match its query")
    if flags & 0x000F:
        raise IntegrationError(f"DNS self-test returned RCODE {flags & 0x000F}")
    if qdcount != 1:
        raise IntegrationError("DNS self-test response has an unexpected question count")
    offset = _skip_dns_name(packet, 12)
    if offset + 4 > len(packet):
        raise IntegrationError("DNS self-test response has a truncated question")
    offset += 4
    answers = []
    for _ in range(ancount):
        offset = _skip_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise IntegrationError("DNS self-test response has a truncated resource record")
        rr_type, rr_class, _, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(packet):
            raise IntegrationError("DNS self-test response has a truncated resource-data field")
        if rr_type == 1 and rr_class == 1 and rdlength == 4:
            answers.append(socket.inet_ntoa(packet[offset:offset + 4]))
        offset += rdlength
    if not answers:
        raise IntegrationError("DNS self-test returned no positive A record")
    return answers


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise IntegrationError("DNS TCP self-test connection closed before the full response arrived")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def query_dns_a(host: str, port: int, *, tcp: bool, timeout: float = 4.0) -> list[str]:
    """Issue a DNS A query and require a positive answer over UDP or TCP."""
    query_id, query = _dns_query_packet("example.com")
    endpoint = f"{host}:{port}"
    if tcp:
        try:
            connection_context = socket.create_connection((host, port), timeout=timeout)
        except TimeoutError:
            raise IntegrationError(f"TCP DNS self-test timed out connecting to {endpoint}") from None
        with connection_context as connection:
            connection.settimeout(timeout)
            try:
                connection.sendall(struct.pack("!H", len(query)) + query)
            except TimeoutError:
                raise IntegrationError(f"TCP DNS self-test timed out sending the query to {endpoint}") from None
            try:
                response_length = struct.unpack("!H", _recv_exact(connection, 2))[0]
            except TimeoutError:
                raise IntegrationError(f"TCP DNS self-test timed out waiting for the response length from {endpoint}") from None
            if response_length < 12 or response_length > 65535:
                raise IntegrationError("DNS TCP self-test returned an invalid response length")
            try:
                response = _recv_exact(connection, response_length)
            except TimeoutError:
                raise IntegrationError(f"TCP DNS self-test timed out reading the response body from {endpoint}") from None
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(timeout)
            try:
                connection.sendto(query, (host, port))
            except TimeoutError:
                raise IntegrationError(f"UDP DNS self-test timed out sending the query to {endpoint}") from None
            try:
                response, source = connection.recvfrom(65535)
            except TimeoutError:
                raise IntegrationError(f"UDP DNS self-test timed out waiting for a response from {endpoint}") from None
            if source[0] != host or source[1] != port:
                raise IntegrationError("DNS UDP self-test response came from an unexpected endpoint")
    return _parse_dns_a_response(response, query_id)


def read_plugin_counters(status_url: str) -> tuple[int, int]:
    if not panel_api_is_local(status_url):
        raise IntegrationError("DoH Health Monitor status URL must use localhost/loopback")
    request = Request(status_url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=3) as response:
            body = response.read(1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise IntegrationError("DoH Health Monitor status API is unavailable during DNS self-test") from None
    status = validate_plugin_status(body)
    queries, failures = status.get("queries"), status.get("failures")
    if (
        isinstance(queries, bool) or not isinstance(queries, int) or queries < 0
        or isinstance(failures, bool) or not isinstance(failures, int) or failures < 0
    ):
        raise IntegrationError("DoH Health Monitor status counters are missing or invalid")
    return queries, failures


def run_tunnel_dns_self_test(port: int, status_url: str) -> None:
    """Test UDP and TCP independently and verify both requests reached the plugin."""
    before_queries, before_failures = read_plugin_counters(status_url)
    if before_failures != 0:
        raise IntegrationError("Plugin failure counter was non-zero before the DNS Tunnel self-test")

    endpoint = f"127.0.0.1:{port}"
    try:
        udp_answers = query_dns_a("127.0.0.1", port, tcp=False)
    except IntegrationError as exc:
        raise IntegrationError(f"UDP Tunnel DNS self-test failed at {endpoint}: {exc}") from None
    print("PASS: UDP Tunnel DNS self-test returned a positive A answer.")
    print("UDP A answers:", ", ".join(udp_answers))

    try:
        tcp_answers = query_dns_a("127.0.0.1", port, tcp=True)
    except IntegrationError as exc:
        raise IntegrationError(f"TCP Tunnel DNS self-test failed at {endpoint}: {exc}") from None
    print("PASS: TCP Tunnel DNS self-test returned a positive A answer.")
    print("TCP A answers:", ", ".join(tcp_answers))

    after_queries, after_failures = read_plugin_counters(status_url)
    if after_queries < before_queries + 2:
        raise IntegrationError(
            "UDP and TCP DNS answers succeeded, but the plugin query counter "
            f"did not increase by two (before={before_queries}, after={after_queries})"
        )
    if after_failures != 0:
        raise IntegrationError("Plugin failure counter was non-zero after the DNS Tunnel self-test")
    print(
        "PASS: plugin query counter increased "
        f"{before_queries} -> {after_queries}; failures remained zero."
    )


def _default_backup_dir() -> Path:
    return Path.home() / ".local" / "state" / "lucx-ui-doh" / "backups"


def _write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=".doh-backup-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def create_backup(snapshot: dict, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = backup_dir / f"lucx-doh-{stamp}-{secrets.token_hex(3)}.json"
    data = {
        "format": 1,
        "tool_version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "before": snapshot,
        "after": None,
        "state": "before-update",
    }
    _write_private_json(path, data)
    return path


def load_backup(path: Path) -> dict:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise IntegrationError("Backup permissions are broader than 0600; refusing to read it")
        data = json.loads(path.read_text(encoding="utf-8"))
    except IntegrationError:
        raise
    except (OSError, json.JSONDecodeError):
        raise IntegrationError("Cannot read backup file") from None
    if not isinstance(data, dict) or data.get("format") != 1:
        raise IntegrationError("Unsupported or invalid backup file")
    if not isinstance(data.get("before"), dict):
        raise IntegrationError("Backup does not contain a valid pre-update snapshot")
    return data


def confirm_restart(action: str, approved_flag: bool) -> None:
    print()
    print("WARNING: LucX-UI panel API changes can cause a full Xray process restart")
    print("when Xray is running. This tool will not restart Xray directly.")
    if approved_flag:
        return
    expected = {"apply": "APPLY", "rollback": "ROLLBACK", "cleanup": "CLEANUP"}.get(action)
    if expected is None:
        raise IntegrationError("Unknown operation requiring restart approval")
    entered = read_tty_confirmation(f"Type {expected} to continue: ")
    if entered != expected:
        raise IntegrationError("Operator confirmation did not match; no API update was sent")


def print_plan(plan: Plan) -> None:
    if plan.changes:
        print("Proposed additions:")
        for change in plan.changes:
            print("  + " + change)
    else:
        print("No DNS integration additions are required.")
    for warning in plan.warnings:
        print("  NOTE: " + warning)
    for blocker in plan.blockers:
        print("  BLOCK: " + blocker)
    if plan.blockers:
        print("Result: NOT SAFE TO APPLY automatically")
    elif plan.changes:
        print("Result: additive plan ready")
    else:
        print("Result: already integrated; no update or restart required")



def build_selective_rollback_config(current: dict, before: dict, after: dict) -> dict:
    """Remove only unchanged DNS objects introduced by this apply; preserve later edits."""
    result = copy.deepcopy(current)

    def tagged(items, tag):
        return [item for item in items if isinstance(item, dict) and item.get("tag") == tag]

    current_outbounds = object_list(result, "outbounds", "outbounds")
    before_outbounds = object_list(before, "outbounds", "before.outbounds")
    after_outbounds = object_list(after, "outbounds", "after.outbounds")
    before_tags = {
        item.get("tag") for item in before_outbounds
        if isinstance(item.get("tag"), str) and item.get("tag")
    }
    # A DNS outbound is owned only when this apply introduced its tag. The
    # preferred name may have been occupied, so rollback must not assume dns-out.
    owned_dns = [
        item for item in after_outbounds
        if isinstance(item.get("tag"), str)
        and item.get("tag") not in before_tags
        and _outbound_matches_dns_endpoint(item)
    ]
    if len(owned_dns) > 1:
        raise IntegrationError("Backup has ambiguous ownership of added local DNS outbounds; selective rollback refused")
    if owned_dns:
        owned = owned_dns[0]
        owned_tag = owned.get("tag")
        present = tagged(current_outbounds, owned_tag)
        if present:
            if len(present) != 1 or canonical(present[0]) != canonical(owned):
                raise IntegrationError(
                    f"Added DNS outbound {owned_tag} was modified after apply; refusing to delete it"
                )
            current_outbounds.remove(present[0])

    before_dns = before.get("dns", {})
    after_dns = after.get("dns", {})
    current_dns = result.get("dns", {})
    if not isinstance(before_dns, dict) or not isinstance(after_dns, dict) or not isinstance(current_dns, dict):
        raise IntegrationError("DNS settings are not objects; selective rollback refused")
    before_servers = before_dns.get("servers", [])
    after_servers = after_dns.get("servers", [])
    current_servers = current_dns.get("servers", [])
    if not all(isinstance(items, list) for items in (before_servers, after_servers, current_servers)):
        raise IntegrationError("DNS server lists are invalid; selective rollback refused")

    def targets_local_dns(server):
        address = ""
        port = None
        if isinstance(server, str):
            address = server
        elif isinstance(server, dict):
            address = server.get("address", "") if isinstance(server.get("address", ""), str) else ""
            port = server.get("port")
        return _split_ip_address(address, port) == ("127.0.0.1", 5355)

    if not any(targets_local_dns(item) for item in before_servers):
        owned_servers = [item for item in after_servers if targets_local_dns(item)]
        if owned_servers:
            if len(owned_servers) != 1:
                raise IntegrationError("Backup has ambiguous ownership of the local DNS server; selective rollback refused")
            present = [item for item in current_servers if targets_local_dns(item)]
            if present:
                if len(present) != 1 or canonical(present[0]) != canonical(owned_servers[0]):
                    raise IntegrationError("DNS server 127.0.0.1:5355 was modified after apply; refusing to delete it")
                current_servers.remove(present[0])

    # Undo only empty container keys introduced by this integration. Do not
    # erase an originally-present DNS object or any later DNS settings.
    if "dns" not in before and current_dns == {"servers": []}:
        result.pop("dns", None)
    elif (
        isinstance(before_dns, dict)
        and "servers" not in before_dns
        and current_dns.get("servers") == []
        and set(current_dns) == {"servers"}
    ):
        current_dns.pop("servers", None)

    before_routing = before.get("routing", {})
    after_routing = after.get("routing", {})
    current_routing = result.get("routing", {})
    if not all(isinstance(item, dict) for item in (before_routing, after_routing, current_routing)):
        raise IntegrationError("Routing settings are not objects; selective rollback refused")
    before_rules = before_routing.get("rules", [])
    after_rules = after_routing.get("rules", [])
    current_rules = current_routing.get("rules", [])
    if not all(isinstance(items, list) for items in (before_rules, after_rules, current_rules)):
        raise IntegrationError("Routing rule lists are invalid; selective rollback refused")

    before_port53 = [rule for rule in before_rules if isinstance(rule, dict) and _global_port53_rule(rule)]
    after_port53 = [rule for rule in after_rules if isinstance(rule, dict) and _global_port53_rule(rule)]
    if not before_port53 and after_port53:
        if len(after_port53) != 1:
            raise IntegrationError("Backup has ambiguous ownership of the port-53 DNS rule; selective rollback refused")
        present = [rule for rule in current_rules if isinstance(rule, dict) and _global_port53_rule(rule)]
        if present:
            if len(present) != 1 or canonical(present[0]) != canonical(after_port53[0]):
                raise IntegrationError("Global port-53 rule was modified after apply; refusing to delete it")
            current_rules.remove(present[0])

    # Do not remove an integration-created outbound if later user changes
    # introduced additional routing/balancer dependencies on its selected tag.
    if owned_dns:
        owned_tag = owned_dns[0].get("tag")
        remaining_rule_refs = [
            index for index, rule in enumerate(current_rules)
            if isinstance(rule, dict) and rule.get("outboundTag") == owned_tag
        ]
        remaining_balancer_refs = []
        balancers = current_routing.get("balancers", [])
        if isinstance(balancers, list):
            for index, balancer in enumerate(balancers):
                if not isinstance(balancer, dict):
                    continue
                selectors = balancer.get("selector", [])
                if isinstance(selectors, str):
                    selectors = [selectors]
                fallback_tag = balancer.get("fallbackTag")
                if (
                    fallback_tag == owned_tag
                    or (
                        isinstance(selectors, list)
                        and any(
                            isinstance(selector, str) and owned_tag.startswith(selector)
                            for selector in selectors
                        )
                    )
                ):
                    remaining_balancer_refs.append(index)
        remaining_observatory_refs = []
        for section_name in ("observatory", "burstObservatory"):
            section = current_routing.get(section_name, result.get(section_name, {}))
            if not isinstance(section, dict):
                continue
            selectors = section.get("subjectSelector", [])
            if isinstance(selectors, str):
                selectors = [selectors]
            if isinstance(selectors, list) and any(
                isinstance(selector, str) and owned_tag.startswith(selector)
                for selector in selectors
            ):
                remaining_observatory_refs.append(section_name)

        remaining_outbound_refs = []
        for index, outbound in enumerate(current_outbounds):
            if not isinstance(outbound, dict) or outbound.get("tag") == owned_tag:
                continue
            proxy_settings = outbound.get("proxySettings")
            if isinstance(proxy_settings, dict) and proxy_settings.get("tag") == owned_tag:
                remaining_outbound_refs.append(index)
            stream_settings = outbound.get("streamSettings")
            if isinstance(stream_settings, dict):
                sockopt = stream_settings.get("sockopt")
                if isinstance(sockopt, dict) and sockopt.get("dialerProxy") == owned_tag:
                    remaining_outbound_refs.append(index)

        if (
            remaining_rule_refs
            or remaining_balancer_refs
            or remaining_observatory_refs
            or remaining_outbound_refs
        ):
            raise IntegrationError(
                f"Added DNS outbound {owned_tag} now has additional user references "
                "(routing rules, balancers, observatory, or outbound chaining); "
                "selective rollback refused to leave broken links"
            )

    return result


def _snapshot_equal(a: dict, b: dict) -> bool:
    return (
        canonical(a.get("xraySetting")) == canonical(b.get("xraySetting"))
        and a.get("outboundTestUrl") == b.get("outboundTestUrl")
    )


def command_check_or_plan(args, client: PanelAPI) -> int:
    snapshot = client.get_snapshot()
    plan = build_plan(snapshot["xraySetting"])
    print("Source: LucX-UI panel API")
    print("API capability: Xray settings read endpoint and response schema are supported.")
    print("API capability: xraySetting and outboundTestUrl metadata were decoded.")
    print("API update endpoint: not probed by a write in read-only mode; validate on staging before production apply.")
    print("Mode: CHECK / READ-ONLY FROM ADAPTER")
    if getattr(args, "base_url", None):
        print("Panel URL was supplied explicitly; SQLite endpoint discovery was skipped.")
    else:
        print("Panel endpoint settings were read from SQLite in mode=ro; the database was not modified.")
    print("Runtime Xray files are not opened.")
    print_plan(plan)
    return 2 if plan.blockers else 0


def remove_verified_backup(path: Path) -> bool:
    """Delete a backup only after the caller has verified apply or rollback."""
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError:
        raise IntegrationError(
            "Verified operation completed, but its private backup could not be deleted; remove it manually"
        ) from None
    return True


def inspect_temporary_leftovers(client: PanelAPI, backup_dir: Path) -> dict:
    """Discover reserved self-test resources through panel APIs, never journal contents."""
    inbounds = client.list_inbounds()
    tunnels = []
    errors = []
    seen_ids = set()
    for item in inbounds:
        remark = item.get("remark")
        if not isinstance(remark, str) or not remark.startswith(TUNNEL_REMARK_PREFIX):
            continue
        inbound_id = item.get("id")
        port = item.get("port")
        marker = remark[len(TUNNEL_REMARK_PREFIX):]
        try:
            if isinstance(inbound_id, bool) or not isinstance(inbound_id, int) or inbound_id <= 0:
                raise IntegrationError("reserved Tunnel has no valid numeric ID")
            if inbound_id in seen_ids:
                raise IntegrationError("duplicate inbound ID in panel response")
            seen_ids.add(inbound_id)
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise IntegrationError("reserved Tunnel has an invalid port")
            expected = build_temporary_tunnel(port, marker)
            verify_temporary_tunnel([item], expected, inbound_id)
            tunnels.append({"expected": expected, "inbound_id": inbound_id, "port": port})
        except IntegrationError as exc:
            errors.append(f"Tunnel marker {remark!r} was not removed because its identity could not be verified: {exc}")

    snapshot = client.get_snapshot()
    outbounds = snapshot["xraySetting"].get("outbounds", [])
    direct_rules_present = False
    if isinstance(outbounds, list):
        for outbound in outbounds:
            if not isinstance(outbound, dict) or outbound.get("tag") != "direct":
                continue
            settings = outbound.get("settings")
            if isinstance(settings, dict) and isinstance(settings.get("finalRules", []), list):
                if any(
                    isinstance(rule, dict) and canonical(rule) == canonical(TEMP_DNS_FINAL_RULE)
                    for rule in settings.get("finalRules", [])
                ):
                    direct_rules_present = True
                    break
    if direct_rules_present:
        try:
            _direct_freedom_outbound(snapshot["xraySetting"])
        except IntegrationError as exc:
            errors.append(f"Temporary finalRule exists but its owning direct outbound is ambiguous: {exc}")

    recovery_dir = backup_dir / "recovery"
    journal_paths = []
    try:
        info = recovery_dir.lstat()
    except FileNotFoundError:
        info = None
    except OSError:
        errors.append("Could not inspect the temporary Tunnel recovery directory")
        info = None
    if info is not None:
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            errors.append(
                "Temporary Tunnel recovery directory must be a private directory owned by the current user with mode 0700"
            )
        else:
            for path in sorted(recovery_dir.glob("lucx-doh-selftest-*.json")):
                try:
                    file_info = path.lstat()
                    if (
                        not stat.S_ISREG(file_info.st_mode)
                        or file_info.st_uid != os.geteuid()
                        or stat.S_IMODE(file_info.st_mode) != 0o600
                    ):
                        raise IntegrationError("recovery marker is not a private regular file owned by the current user")
                    journal_paths.append(path)
                except (OSError, IntegrationError) as exc:
                    errors.append(f"Recovery marker {path.name!r} cannot be safely removed: {exc}")

    return {
        "tunnels": tunnels,
        "final_rule_present": direct_rules_present,
        "journal_paths": journal_paths,
        "errors": errors,
    }


def cleanup_temporary_leftovers(client: PanelAPI, backup_dir: Path, discovered: dict) -> None:
    """Independently remove verified reserved resources, then clear opaque journal markers."""
    errors = list(discovered.get("errors", []))

    for resource in discovered.get("tunnels", []):
        expected = resource["expected"]
        inbound_id = resource["inbound_id"]
        port = resource["port"]
        try:
            removed = cleanup_temporary_tunnel(client, expected, inbound_id)
            if removed:
                wait_for_tunnel_port_closed(port)
        except Exception as exc:
            errors.append(f"Tunnel {expected['remark']}: {exc}")

    if discovered.get("final_rule_present"):
        try:
            cleanup_temporary_dns_final_rule(client, TEMP_DNS_FINAL_RULE)
        except Exception as exc:
            errors.append(f"temporary finalRule: {exc}")

    # Verify both resource classes independently, even when one cleanup failed.
    try:
        remaining = [
            item for item in client.list_inbounds()
            if isinstance(item.get("remark"), str)
            and item["remark"].startswith(TUNNEL_REMARK_PREFIX)
        ]
        if remaining:
            errors.append("One or more reserved temporary Tunnel inbounds remain after cleanup")
    except Exception as exc:
        errors.append(f"Could not verify temporary Tunnel absence: {exc}")

    try:
        current = client.get_snapshot()["xraySetting"]
        outbounds = current.get("outbounds", [])
        still_present = False
        if isinstance(outbounds, list):
            for outbound in outbounds:
                if not isinstance(outbound, dict) or outbound.get("tag") != "direct":
                    continue
                settings = outbound.get("settings")
                final_rules = settings.get("finalRules", []) if isinstance(settings, dict) else []
                if isinstance(final_rules, list) and any(
                    isinstance(rule, dict) and canonical(rule) == canonical(TEMP_DNS_FINAL_RULE)
                    for rule in final_rules
                ):
                    still_present = True
        if still_present:
            errors.append("Temporary DNS finalRule remains after cleanup")
    except Exception as exc:
        errors.append(f"Could not verify temporary finalRule absence: {exc}")

    if errors:
        raise IntegrationError("; ".join(errors))

    # Journal filenames are only opaque recovery markers here. Resource identity
    # was established from the live API; journal JSON is intentionally not read.
    for path in discovered.get("journal_paths", []):
        try:
            info = path.lstat()
            if (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600
            ):
                path.unlink()
            else:
                raise IntegrationError("recovery marker permissions changed during cleanup")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise IntegrationError(f"Resources were cleaned but recovery marker {path.name!r} could not be removed: {exc}") from None

    print(
        "PASS: pre-existing temporary Tunnel/finalRule resources were checked through the panel API; "
        "verified leftovers and opaque recovery markers were cleaned."
    )


def command_apply(
    args, client: PanelAPI, *, perform_preflight: bool = False
) -> int:
    backup_dir = Path(args.backup_dir).expanduser()

    # First discover and clean only leftovers bearing our reserved identity.
    # No recovery journal contents or system logs are read for this decision.
    leftovers = inspect_temporary_leftovers(client, backup_dir)
    has_leftovers = bool(
        leftovers["tunnels"] or leftovers["final_rule_present"]
    )
    cleanup_approved = False
    if has_leftovers:
        confirm_restart("apply", args.approve_restart)
        cleanup_approved = True
    try:
        cleanup_temporary_leftovers(client, backup_dir, leftovers)
    except IntegrationError as exc:
        print("ERROR: previous temporary self-test resources could not be safely cleaned.")
        print("No permanent DNS integration changes were attempted.")
        print("Reason:", exc)
        return 2

    # A stale Tunnel/finalRule must be cleaned even if the plugin is currently
    # unhealthy. Only after cleanup do we enforce the normal apply preflight.
    if perform_preflight:
        check_plugin_health(args.plugin_service, args.plugin_status_url, args.plugin_port)
        check_xray_compatibility(args.xray_bin)

    snapshot = client.get_snapshot()
    plan = build_plan(snapshot["xraySetting"])
    print_plan(plan)
    if plan.blockers:
        return 2
    if not plan.changes:
        print("No permanent Xray settings update is required.")
        if not cleanup_approved:
            confirm_restart("apply", args.approve_restart)
        try:
            run_temporary_tunnel_test(
                client,
                getattr(args, "plugin_status_url", DEFAULT_PLUGIN_STATUS_URL),
                backup_dir,
            )
        except IntegrationError as exc:
            print("ERROR: existing DNS integration failed the end-to-end Tunnel test.")
            print("No permanent Xray settings update was required.")
            print("Reason:", exc)
            return 2
        return 0

    if not cleanup_approved:
        confirm_restart("apply", args.approve_restart)
    backup_path = create_backup(snapshot, backup_dir)
    print("Private backup created (mode 0600):", backup_path)

    api_error = None
    try:
        client.update(plan.proposed, snapshot["outboundTestUrl"])
    except IntegrationError as exc:
        api_error = str(exc)

    try:
        after = client.get_snapshot()
    except IntegrationError:
        print("ERROR: read-back verification could not be completed.")
        print("The pre-update backup is preserved; do not retry blindly.")
        print("Backup:", backup_path)
        if api_error:
            print("API update result: " + api_error)
        return 2

    backup_data = load_backup(backup_path)
    backup_data["after"] = after
    backup_data["state"] = "update-attempted"
    _write_private_json(backup_path, backup_data)

    expected = plan.expected_saved
    if canonical(after["xraySetting"]) != canonical(expected):
        print("ERROR: panel read-back differs from the predicted additive result.")
        print("No automatic rollback was attempted.")
        print("Review the panel state; guarded rollback is available only while the current template still matches the saved after-snapshot.")
        print("Backup:", backup_path)
        if api_error:
            print("API update result: " + api_error)
        return 2

    backup_data["state"] = "applied-and-verified"
    _write_private_json(backup_path, backup_data)
    if api_error:
        print("ERROR: panel returned an update error although read-back matches the proposed configuration.")
        print("Check panel/Xray status before taking further action.")
        print("Backup:", backup_path)
        return 2

    print("PASS: panel API read-back matches the predicted additive configuration.")
    print("Existing outbounds, DNS entries, and user routing rules were preserved by the predicted transformation.")
    print("Persistent rollback snapshot retained (mode 0600):", backup_path)
    print("Use the rollback action with this backup path to undo the integration later.")
    print("Rollback removes only unchanged DNS integration objects owned by this apply; unrelated later panel changes are preserved.")
    print("Check Xray status in LucX-UI; a running core may have been fully restarted by the panel.")

    try:
        run_temporary_tunnel_test(
            client,
            getattr(args, "plugin_status_url", DEFAULT_PLUGIN_STATUS_URL),
            Path(args.backup_dir).expanduser(),
        )
    except IntegrationError as exc:
        print("ERROR: permanent DNS integration was applied, but the end-to-end Tunnel test did not pass.")
        print("The persistent rollback snapshot is retained; no automatic rollback was attempted.")
        print("Reason:", exc)
        print("Backup:", backup_path)
        return 2
    return 0


def command_rollback(args, client: PanelAPI) -> int:
    backup_path = Path(args.backup).expanduser()
    backup_data = load_backup(backup_path)
    after = backup_data.get("after")
    if not isinstance(after, dict):
        raise IntegrationError("Backup has no verified after-snapshot; selective rollback is unavailable")

    before = backup_data["before"]
    current = client.get_snapshot()
    rollback_config = build_selective_rollback_config(
        current["xraySetting"], before["xraySetting"], after["xraySetting"]
    )
    expected = panel_normalize_dns_allow_rules(rollback_config)

    # Keep current panel metadata and all unrelated settings; only the three
    # DNS objects owned by this apply are removed.
    confirm_restart("rollback", args.approve_restart)
    try:
        client.update(rollback_config, current["outboundTestUrl"])
    except IntegrationError as exc:
        print("ERROR: panel reported a selective rollback update error: " + str(exc))
        print("The backup remains available:", backup_path)
        return 2

    restored = client.get_snapshot()
    if canonical(restored["xraySetting"]) != canonical(expected):
        print("ERROR: selective rollback read-back differs from the expected panel-normalized configuration.")
        print("No further update was sent. Backup:", backup_path)
        return 2

    print("PASS: selective rollback verified through the panel API.")
    print("Only the unchanged DNS outbound, 127.0.0.1:5355 DNS server, and global port-53 rule introduced by this apply were removed.")
    print("Unrelated current panel settings and metadata were preserved.")
    try:
        remove_verified_backup(backup_path)
        print("Temporary rollback backup deleted after successful restoration.")
    except IntegrationError as exc:
        print("WARNING:", exc)
        print("Backup retained at:", backup_path)
    print("The panel may have fully restarted Xray while applying selective rollback.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe additive DoH integration for LucX-UI using its panel API"
    )
    parser.add_argument(
        "--base-url",
        help="Panel origin plus any web base path; auto-detected from local SQLite when omitted",
    )
    parser.add_argument(
        "--panel-db",
        help="Custom LucX-UI SQLite database path for read-only URL discovery (default: /etc/x-ui/x-ui.db)",
    )
    parser.add_argument(
        "--panel-auth-file",
        default=str(DEFAULT_PANEL_AUTH_FILE),
        help="Root-only local credential store used only when the installer token file is unavailable",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--plugin-service", default=DEFAULT_PLUGIN_SERVICE,
                        help="systemd unit for DoH Health Monitor")
    parser.add_argument("--plugin-status-url", default=DEFAULT_PLUGIN_STATUS_URL,
                        help="local DoH Health Monitor status endpoint")
    parser.add_argument("--plugin-port", type=int, default=DEFAULT_PLUGIN_PORT,
                        help="local DoH Health Monitor TCP/UDP listener port")
    parser.add_argument("--xray-bin", help="Path to local Xray executable (auto-detected when omitted)")
    # Kept as a compatibility alias for older deployment commands; version is informational.
    parser.add_argument("--allow-untested-xray", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--allow-insecure-http", action="store_true", help="Allow non-loopback HTTP (not recommended)")
    parser.add_argument(
        "--tls-mode",
        choices=("auto", "http", "ip", "domain"),
        default="auto",
        help="TLS identity mode for explicit/overridden endpoints: auto, http, ip, or domain",
    )
    parser.add_argument(
        "--tls-name",
        help="Expected certificate IP (for --tls-mode ip) or DNS name (for --tls-mode domain)",
    )
    parser.add_argument(
        "--backup-dir",
        default=str(_default_backup_dir()),
        help="Local directory for 0600 backups (default: user state directory)",
    )
    parser.add_argument(
        "--approve-restart",
        action="store_true",
        help="Explicitly approve the full Xray restart that the panel API may perform",
    )
    parser.add_argument("action", choices=("check", "plan", "apply", "rollback", "cleanup-test"))
    parser.add_argument("--recovery-journal", help="Private temporary Tunnel recovery journal for cleanup-test")
    parser.add_argument("--backup", help="Backup file required for rollback")
    args = parser.parse_args()

    if args.action == "rollback" and not args.backup:
        parser.error("rollback requires --backup")
    if args.action == "cleanup-test" and not args.recovery_journal:
        parser.error("cleanup-test requires --recovery-journal")
    if args.action != "cleanup-test" and args.recovery_journal:
        parser.error("--recovery-journal is only valid with cleanup-test")

    try:
        if os.geteuid() != 0:
            raise IntegrationError("Run this tool as root directly on the LucX-UI VPS")
        if args.base_url and args.panel_db:
            raise IntegrationError("--panel-db is only valid when --base-url is omitted")
        endpoint = (
            PanelEndpoint(args.base_url)
            if args.base_url
            else detect_panel_endpoint(Path(args.panel_db).expanduser() if args.panel_db else None)
        )
        if args.base_url and urlsplit(args.base_url).scheme == "https" and args.tls_mode == "auto":
            raise IntegrationError(
                "An explicit HTTPS --base-url requires --tls-mode ip/domain and --tls-name; "
                "certificate identity cannot be inferred from a loopback URL"
            )
        if args.tls_mode == "http":
            if urlsplit(endpoint.base_url).scheme != "http" or args.tls_name:
                raise IntegrationError("--tls-mode http requires an HTTP --base-url and no --tls-name")
            endpoint = PanelEndpoint(endpoint.base_url, endpoint.host_header)
        elif args.tls_mode in {"ip", "domain"}:
            if urlsplit(endpoint.base_url).scheme != "https" or not args.tls_name:
                raise IntegrationError("--tls-mode ip/domain requires HTTPS and --tls-name")
            if args.tls_mode == "ip":
                try:
                    expected_ip = str(ipaddress.ip_address(args.tls_name))
                except ValueError:
                    raise IntegrationError("--tls-name must be an IP address for --tls-mode ip") from None
                endpoint = PanelEndpoint(
                    endpoint.base_url, endpoint.host_header, "localhost", expected_ip
                )
            else:
                parsed_name = urlsplit("//" + args.tls_name)
                try:
                    explicit_name_port = parsed_name.port
                except ValueError:
                    explicit_name_port = -1
                try:
                    ipaddress.ip_address(parsed_name.hostname or "")
                    name_is_ip = True
                except ValueError:
                    name_is_ip = False
                if (
                    not parsed_name.hostname or parsed_name.username or parsed_name.password
                    or explicit_name_port is not None or parsed_name.path or parsed_name.query
                    or parsed_name.fragment or any(char.isspace() for char in args.tls_name)
                    or name_is_ip
                ):
                    raise IntegrationError("--tls-name must be a plain DNS hostname for --tls-mode domain")
                endpoint = PanelEndpoint(
                    endpoint.base_url,
                    f"{parsed_name.hostname}:{urlsplit(endpoint.base_url).port}",
                    parsed_name.hostname,
                    None,
                )
        elif args.tls_name:
            raise IntegrationError("--tls-name requires --tls-mode ip or domain")
        if not panel_api_is_local(endpoint.base_url):
            raise IntegrationError("Panel API URL must use localhost/loopback; run the adapter on the target VPS")
        parsed_endpoint = urlsplit(endpoint.base_url)
        path_state = "root path" if not parsed_endpoint.path else "configured path (hidden)"
        print(
            f"Panel endpoint {'supplied' if args.base_url else 'auto-detected'}: "
            f"{parsed_endpoint.scheme}://127.0.0.1:{parsed_endpoint.port} ({path_state})"
        )
        if endpoint.host_header:
            print("Panel domain validation: configured Host header and TLS SNI will be used.")
        if args.action not in {"cleanup-test", "apply"}:
            check_plugin_health(args.plugin_service, args.plugin_status_url, args.plugin_port)
            check_xray_compatibility(args.xray_bin)
        token = resolve_panel_api_token(Path(args.panel_auth_file))
        client = PanelAPI(
            endpoint.base_url,
            token,
            timeout=args.timeout,
            allow_insecure_http=args.allow_insecure_http,
            host_header=endpoint.host_header,
            tls_server_name=endpoint.tls_server_name,
            tls_verify_ip=endpoint.tls_verify_ip,
        )
        if args.action in {"check", "plan"}:
            return command_check_or_plan(args, client)
        if args.action == "apply":
            return command_apply(args, client, perform_preflight=True)
        if args.action == "cleanup-test":
            journal_path = Path(args.recovery_journal).expanduser()
            journal = _load_recovery_journal(journal_path)
            inbound_id = journal.get("inbound_id")
            before_cleanup = client.list_inbounds()
            if inbound_id is not None:
                resource_present = any(
                    isinstance(item, dict) and item.get("id") == inbound_id
                    for item in before_cleanup
                )
            else:
                resource_present = any(
                    isinstance(item, dict) and item.get("remark") == journal["inbound"]["remark"]
                    for item in before_cleanup
                )
            final_rule = journal.get("final_rule")
            rule_present = False
            if final_rule is not None:
                current_snapshot = client.get_snapshot()
                current_direct = _direct_freedom_outbound(current_snapshot["xraySetting"])
                current_final_rules = current_direct["settings"].get("finalRules", [])
                rule_present = isinstance(current_final_rules, list) and any(
                    isinstance(item, dict)
                    and canonical(item) == canonical(final_rule)
                    for item in current_final_rules
                )
            if resource_present or rule_present:
                confirm_restart("cleanup", args.approve_restart)
            removed = cleanup_temporary_tunnel(client, journal["inbound"], inbound_id)
            if inbound_id is not None or removed:
                wait_for_tunnel_port_closed(journal["inbound"]["port"])
            if final_rule is not None:
                cleanup_temporary_dns_final_rule(client, final_rule)
            journal_path.unlink(missing_ok=True)
            print("PASS: temporary Tunnel and DNS finalRule recovery cleanup verified; journal removed.")
            return 0
        return command_rollback(args, client)
    except IntegrationError as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(
            "\nInterrupted. If a temporary Tunnel was being tested, its finally cleanup was attempted; "
            "inspect any recovery journal before retrying.",
            file=sys.stderr,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())