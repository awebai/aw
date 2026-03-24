#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import contextlib
import http.client
import http.server
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CLOUD_DIR = (REPO_ROOT.parent / "aweb-cloud").resolve()
DEFAULT_REPORT = REPO_ROOT / "artifacts" / "local-cloud-validation-report.json"


@dataclass
class ExpectedCall:
    method: str
    path_prefix: str


@dataclass
class RecordedRequest:
    method: str
    path: str
    query: str
    status_code: int
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_body_text: str | None = None
    request_body_json: Any | None = None


@dataclass
class CommandResult:
    name: str
    cwd: str
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    requests: list[RecordedRequest] = field(default_factory=list)
    expected: list[ExpectedCall] = field(default_factory=list)
    missing_expected: list[str] = field(default_factory=list)
    parsed_json: Any | None = None


class ValidationError(RuntimeError):
    pass


def run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    name: str,
    allow_failure: bool = False,
) -> CommandResult:
    proc = subprocess.run(
        argv,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
    )
    result = CommandResult(
        name=name,
        cwd=str(cwd),
        argv=argv,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
    if not allow_failure and proc.returncode != 0:
        raise ValidationError(
            f"{name} failed with exit code {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    return result


def find_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def random_secret() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(alphabet) for _ in range(48))


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def rewrite_upstream_urls(value: Any, upstream_base: str, proxy_base: str) -> Any:
    if isinstance(value, dict):
        return {key: rewrite_upstream_urls(item, upstream_base, proxy_base) for key, item in value.items()}
    if isinstance(value, list):
        return [rewrite_upstream_urls(item, upstream_base, proxy_base) for item in value]
    if isinstance(value, str) and value.startswith(upstream_base):
        return proxy_base + value[len(upstream_base):]
    return value


class RecordingProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            super().handle()

    def _handle(self) -> None:
        server = self.server
        assert isinstance(server, RecordingProxyServer)

        raw_body = b""
        content_length = self.headers.get("Content-Length")
        if content_length:
            raw_body = self.rfile.read(int(content_length))

        upstream = http.client.HTTPConnection(server.target_host, server.target_port, timeout=30)
        path = self.path
        headers = {key: value for key, value in self.headers.items()}
        headers.pop("Content-Length", None)
        upstream.request(self.command, path, body=raw_body if raw_body else None, headers=headers)
        response = upstream.getresponse()
        response_body = response.read()
        content_type = dict(response.getheaders()).get("Content-Type", "")
        if "application/json" in content_type and response_body:
            with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
                payload = json.loads(response_body.decode("utf-8"))
                rewritten = rewrite_upstream_urls(payload, server.target_base_url, server.public_base_url)
                response_body = json.dumps(rewritten).encode("utf-8")

        parsed = urlparse(path)
        body_text = raw_body.decode("utf-8", errors="replace") if raw_body else None
        body_json = None
        if body_text:
            with contextlib.suppress(json.JSONDecodeError):
                body_json = json.loads(body_text)
        record = RecordedRequest(
            method=self.command,
            path=parsed.path,
            query=parsed.query,
            status_code=response.status,
            request_headers={key: value for key, value in self.headers.items()},
            response_headers={key: value for key, value in response.getheaders()},
            request_body_text=body_text,
            request_body_json=body_json,
        )
        server.requests.append(record)

        self.send_response(response.status, response.reason)
        for key, value in response.getheaders():
            lowered = key.lower()
            if lowered in {"transfer-encoding", "connection"}:
                continue
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        if response_body:
            self.wfile.write(response_body)
        upstream.close()

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


class RecordingProxyServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], target_url: str):
        parsed = urlparse(target_url)
        if parsed.scheme != "http":
            raise ValidationError(f"proxy target must be http, got: {target_url}")
        super().__init__(server_address, RecordingProxyHandler)
        self.target_host = parsed.hostname or "127.0.0.1"
        self.target_port = parsed.port or 80
        self.target_base_url = f"http://{self.target_host}:{self.target_port}"
        self.public_base_url = f"http://127.0.0.1:{server_address[1]}"
        self.requests: list[RecordedRequest] = []


class RunningProxy:
    def __init__(self, target_url: str):
        self.port = find_free_port()
        self.server = RecordingProxyServer(("127.0.0.1", self.port), target_url)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def snapshot(self) -> int:
        return len(self.server.requests)

    def requests_since(self, snapshot: int) -> list[RecordedRequest]:
        return self.server.requests[snapshot:]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class CloudStack:
    def __init__(self, *, cloud_dir: Path, env_file: Path, image_name: str, compose_project: str):
        self.cloud_dir = cloud_dir
        self.env_file = env_file
        self.image_name = image_name
        self.compose_project = compose_project

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["COMPOSE_PROJECT_NAME"] = self.compose_project
        return env

    def up(self) -> None:
        run(
            ["make", "local-container", f"LOCAL_ENV_FILE={self.env_file}", f"LOCAL_IMAGE={self.image_name}"],
            cwd=self.cloud_dir,
            env=self._env(),
            name="aweb-cloud local-container",
        )

    def down(self) -> None:
        run(
            ["make", "local-container-down", f"LOCAL_ENV_FILE={self.env_file}", f"LOCAL_IMAGE={self.image_name}"],
            cwd=self.cloud_dir,
            env=self._env(),
            name="aweb-cloud local-container-down",
            allow_failure=True,
        )


class Validator:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.tmp_root = Path(tempfile.mkdtemp(prefix="aw-local-cloud-validate-"))
        self.home = self.tmp_root / "home"
        self.xdg = self.tmp_root / "xdg"
        self.workspaces = self.tmp_root / "workspaces"
        self.bin_dir = self.tmp_root / "bin"
        self.artifacts = self.tmp_root / "artifacts"
        self.home.mkdir(parents=True, exist_ok=True)
        self.xdg.mkdir(parents=True, exist_ok=True)
        self.workspaces.mkdir(parents=True, exist_ok=True)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.cloud_dir = args.cloud_dir.resolve()
        self.cloud_port = args.cloud_port or find_free_port()
        self.postgres_port = args.postgres_port or find_free_port()
        self.redis_port = args.redis_port or find_free_port()
        self.env_file = self.tmp_root / "aweb-cloud.local.env"
        self.image_name = f"aweb-cloud-aw-validate-{int(time.time())}"
        self.compose_project = f"awvalidate{int(time.time())}"
        self.report_path = args.report.resolve()
        self.proxy: RunningProxy | None = None
        self.cloud: CloudStack | None = None
        self.aw_bin = self.bin_dir / "aw"
        self.command_results: list[CommandResult] = []
        self.project_api_key: str | None = None
        self.created_project_slug = args.project_slug
        self.created_namespace_slug = args.namespace_slug or args.project_slug
        self.invite_token: str | None = None
        self.revocable_invite_prefix: str | None = None
        self.failure: str | None = None
        atexit.register(self._cleanup)

    def _cleanup(self) -> None:
        if self.proxy is not None:
            self.proxy.close()
            self.proxy = None
        if self.cloud is not None and not self.args.leave_stack_running:
            self.cloud.down()
            self.cloud = None
        if not self.args.keep_temp:
            shutil.rmtree(self.tmp_root, ignore_errors=True)

    def write_cloud_env(self) -> None:
        db_password = random_secret()
        content = textwrap.dedent(
            f"""\
            POSTGRES_USER=aweb
            POSTGRES_PASSWORD={db_password}
            POSTGRES_DB=aweb_cloud
            POSTGRES_PORT={self.postgres_port}
            REDIS_PORT={self.redis_port}
            AWEB_CLOUD_PORT={self.cloud_port}
            ENVIRONMENT=local-container
            LOG_LEVEL=INFO
            DATABASE_URL=postgresql://aweb:{db_password}@postgres:5432/aweb_cloud
            REDIS_URL=redis://redis:6379/0
            SECRET_KEY={random_secret()}
            SESSION_SECRET_KEY={random_secret()}
            JWT_SECRET_KEY={random_secret()}
            AWEB_INTERNAL_AUTH_SECRET={random_secret()}
            FRONTEND_URL=http://localhost:{self.cloud_port}
            API_URL=http://localhost:{self.cloud_port}
            API_BASE_URL=http://localhost:{self.cloud_port}
            CORS_ORIGINS=["http://localhost:{self.cloud_port}"]
            GOOGLE_CLIENT_ID=dummy-google-id
            GOOGLE_CLIENT_SECRET=dummy-google-secret
            GITHUB_CLIENT_ID=dummy-github-id
            GITHUB_CLIENT_SECRET=dummy-github-secret
            STRIPE_SECRET_KEY=sk_test_dummy
            STRIPE_PUBLISHABLE_KEY=pk_test_dummy
            STRIPE_WEBHOOK_SECRET=whsec_dummy
            STRIPE_PRO_PRICE_ID=price_dummy_pro
            STRIPE_BUSINESS_PRICE_ID=price_dummy_business
            EMAIL_ENABLED=false
            AWS_REGION=us-east-1
            AWS_ACCESS_KEY_ID=dummy
            AWS_SECRET_ACCESS_KEY=dummy
            SENTRY_DSN=
            SENTRY_ENVIRONMENT=local-container
            SENTRY_TRACES_SAMPLE_RATE=0.0
            """
        )
        self.env_file.write_text(content, encoding="utf-8")

    def start_stack(self) -> None:
        self.write_cloud_env()
        self.cloud = CloudStack(
            cloud_dir=self.cloud_dir,
            env_file=self.env_file,
            image_name=self.image_name,
            compose_project=self.compose_project,
        )
        self.cloud.up()

    def start_proxy(self) -> None:
        self.proxy = RunningProxy(f"http://127.0.0.1:{self.cloud_port}")

    def build_aw(self) -> None:
        run(
            ["go", "build", "-o", str(self.aw_bin), "./cmd/aw"],
            cwd=REPO_ROOT,
            env={**os.environ, "GOCACHE": str(REPO_ROOT / ".cache" / "go-build"), "GOMODCACHE": str(REPO_ROOT / ".cache" / "go-mod")},
            name="build aw",
        )

    def base_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(self.home),
                "XDG_CONFIG_HOME": str(self.xdg),
                "USER": "validator",
                "AWEB_HUMAN": "Validator",
                "NO_COLOR": "1",
            }
        )
        return env

    def make_git_repo(self, name: str) -> Path:
        repo = self.workspaces / name
        repo.mkdir(parents=True, exist_ok=True)
        env = self.base_env()
        run(["git", "init"], cwd=repo, env=env, name=f"git init {name}")
        run(["git", "config", "user.name", "Validator"], cwd=repo, env=env, name=f"git config user.name {name}")
        run(["git", "config", "user.email", "validator@example.com"], cwd=repo, env=env, name=f"git config user.email {name}")
        (repo / "README.md").write_text(f"# {name}\n", encoding="utf-8")
        run(["git", "add", "README.md"], cwd=repo, env=env, name=f"git add {name}")
        run(["git", "commit", "-m", "init"], cwd=repo, env=env, name=f"git commit {name}")
        run(
            ["git", "remote", "add", "origin", f"https://github.com/awebai/{name}.git"],
            cwd=repo,
            env=env,
            name=f"git remote add {name}",
        )
        return repo

    def make_plain_dir(self, name: str) -> Path:
        directory = self.workspaces / name
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def run_aw(
        self,
        name: str,
        *,
        cwd: Path,
        args: list[str],
        env_overrides: dict[str, str] | None = None,
        expected: list[ExpectedCall] | None = None,
    ) -> CommandResult:
        if self.proxy is None:
            raise ValidationError("proxy is not running")
        env = self.base_env()
        if env_overrides:
            env.update({key: value for key, value in env_overrides.items() if value is not None})
        snapshot = self.proxy.snapshot()
        result = run([str(self.aw_bin), *args], cwd=cwd, env=env, name=name, allow_failure=True)
        result.requests = self.proxy.requests_since(snapshot)
        result.expected = expected or []
        result.missing_expected = find_missing_expected(result.requests, result.expected)
        stdout = result.stdout.strip()
        if stdout.startswith("{") or stdout.startswith("["):
            with contextlib.suppress(json.JSONDecodeError):
                result.parsed_json = json.loads(stdout)
        self.command_results.append(result)
        if result.exit_code != 0:
            raise ValidationError(
                f"{name} failed with exit code {result.exit_code}\n"
                f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
            )
        if result.missing_expected:
            raise ValidationError(
                f"{name} did not hit expected endpoints: {', '.join(result.missing_expected)}\n"
                f"observed: {format_observed_requests(result.requests)}"
            )
        return result

    def run_suite(self) -> None:
        proxy_url = self.proxy.base_url if self.proxy is not None else ""

        project_repo = self.make_git_repo("validate-project")
        create = self.run_aw(
            "project-create-ephemeral",
            cwd=project_repo,
            args=[
                "project",
                "create",
                "--json",
                "--server",
                proxy_url,
                "--project",
                self.created_project_slug,
                "--namespace",
                self.created_namespace_slug,
                "--alias",
                "architect",
                "--role",
                "developer",
            ],
            expected=[
                ExpectedCall("GET", "/api/v1/agents/heartbeat"),
                ExpectedCall("POST", "/api/v1/create-project"),
                ExpectedCall("GET", "/api/v1/policies/active"),
                ExpectedCall("POST", "/api/v1/workspaces/register"),
            ],
        )
        create_json = ensure_json_dict(create, "project-create-ephemeral")
        self.project_api_key = str(create_json["api_key"])

        self.run_aw(
            "project-current",
            cwd=project_repo,
            args=["project", "--json"],
            expected=[ExpectedCall("GET", "/api/v1/projects/current")],
        )
        self.run_aw(
            "policy-show",
            cwd=project_repo,
            args=["policy", "show", "--json"],
            expected=[ExpectedCall("GET", "/api/v1/policies/active")],
        )
        self.run_aw(
            "whoami",
            cwd=project_repo,
            args=["whoami", "--json"],
            expected=[ExpectedCall("GET", "/api/v1/auth/introspect")],
        )
        self.run_aw(
            "identities",
            cwd=project_repo,
            args=["identities", "--json"],
            expected=[ExpectedCall("GET", "/api/v1/agents")],
        )
        self.run_aw(
            "identity-log",
            cwd=project_repo,
            args=["identity", "log"],
            expected=[ExpectedCall("GET", "/api/v1/agents/me/log")],
        )
        self.run_aw(
            "identity-access-mode-get",
            cwd=project_repo,
            args=["identity", "access-mode", "--json"],
            expected=[
                ExpectedCall("GET", "/api/v1/auth/introspect"),
                ExpectedCall("GET", "/api/v1/agents"),
            ],
        )
        self.run_aw(
            "identity-access-mode-set",
            cwd=project_repo,
            args=["identity", "access-mode", "contacts_only", "--json"],
            expected=[
                ExpectedCall("GET", "/api/v1/auth/introspect"),
                ExpectedCall("PATCH", "/api/v1/agents/"),
            ],
        )
        self.run_aw(
            "workspace-status-project",
            cwd=project_repo,
            args=["workspace", "status", "--json"],
            expected=[ExpectedCall("GET", "/api/v1/workspaces/team")],
        )

        init_repo = self.make_git_repo("validate-init")
        init_result = self.run_aw(
            "existing-project-init",
            cwd=init_repo,
            args=[
                "init",
                "--json",
                "--server",
                proxy_url,
                "--alias",
                "analyst",
                "--role",
                "developer",
            ],
            env_overrides={"AWEB_API_KEY": self.project_api_key},
            expected=[
                ExpectedCall("GET", "/api/v1/agents/heartbeat"),
                ExpectedCall("POST", "/api/v1/workspaces/init"),
                ExpectedCall("GET", "/api/v1/policies/active"),
                ExpectedCall("POST", "/api/v1/workspaces/register"),
            ],
        )
        init_json = ensure_json_dict(init_result, "existing-project-init")

        local_dir = self.make_plain_dir("validate-local-dir")
        self.run_aw(
            "existing-project-init-local-dir",
            cwd=local_dir,
            args=[
                "init",
                "--json",
                "--server",
                proxy_url,
                "--alias",
                "localdir",
            ],
            env_overrides={"AWEB_API_KEY": self.project_api_key},
            expected=[
                ExpectedCall("GET", "/api/v1/agents/heartbeat"),
                ExpectedCall("POST", "/api/v1/workspaces/init"),
                ExpectedCall("POST", "/api/v1/workspaces/attach"),
            ],
        )

        invite_create = self.run_aw(
            "spawn-create-invite",
            cwd=project_repo,
            args=["spawn", "create-invite", "--alias", "reviewer", "--json"],
            expected=[ExpectedCall("POST", "/api/v1/spawn/create-invite")],
        )
        invite_json = ensure_json_dict(invite_create, "spawn-create-invite")
        self.invite_token = str(invite_json["token"])

        self.run_aw(
            "spawn-list-invites",
            cwd=project_repo,
            args=["spawn", "list-invites", "--json"],
            expected=[ExpectedCall("GET", "/api/v1/spawn/invites")],
        )

        invite_for_revoke = self.run_aw(
            "spawn-create-invite-revoke-target",
            cwd=project_repo,
            args=["spawn", "create-invite", "--alias", "revoke-me", "--json"],
            expected=[ExpectedCall("POST", "/api/v1/spawn/create-invite")],
        )
        invite_for_revoke_json = ensure_json_dict(invite_for_revoke, "spawn-create-invite-revoke-target")
        self.revocable_invite_prefix = str(invite_for_revoke_json["token_prefix"])

        child_repo = self.make_git_repo("validate-spawn-child")
        self.run_aw(
            "spawn-accept-invite",
            cwd=child_repo,
            args=[
                "spawn",
                "accept-invite",
                self.invite_token,
                "--json",
                "--server",
                proxy_url,
                "--alias",
                "reviewer",
                "--role",
                "developer",
            ],
            expected=[
                ExpectedCall("POST", "/api/v1/spawn/accept-invite"),
                ExpectedCall("GET", "/api/v1/policies/active"),
                ExpectedCall("POST", "/api/v1/workspaces/register"),
            ],
        )

        self.run_aw(
            "spawn-revoke-invite",
            cwd=project_repo,
            args=["spawn", "revoke-invite", self.revocable_invite_prefix, "--json"],
            expected=[
                ExpectedCall("GET", "/api/v1/spawn/invites"),
                ExpectedCall("DELETE", "/api/v1/spawn/invites/"),
            ],
        )

        connect_home = self.tmp_root / "connect-home"
        connect_xdg = self.tmp_root / "connect-xdg"
        connect_dir = self.make_plain_dir("validate-connect")
        connect_env = self.base_env()
        connect_env["HOME"] = str(connect_home)
        connect_env["XDG_CONFIG_HOME"] = str(connect_xdg)
        connect_env["AWEB_URL"] = proxy_url
        connect_env["AWEB_API_KEY"] = str(init_json["api_key"])
        snapshot = self.proxy.snapshot()
        connect_result = run([str(self.aw_bin), "connect", "--json"], cwd=connect_dir, env=connect_env, name="connect")
        connect_result.requests = self.proxy.requests_since(snapshot)
        connect_result.expected = [ExpectedCall("GET", "/api/v1/auth/introspect"), ExpectedCall("GET", "/api/v1/agents/resolve/")]
        connect_result.missing_expected = find_missing_expected(connect_result.requests, connect_result.expected)
        if connect_result.missing_expected:
            raise ValidationError(
                f"connect did not hit expected endpoints: {', '.join(connect_result.missing_expected)}\n"
                f"observed: {format_observed_requests(connect_result.requests)}"
            )
        stdout = connect_result.stdout.strip()
        if stdout.startswith("{") or stdout.startswith("["):
            with contextlib.suppress(json.JSONDecodeError):
                connect_result.parsed_json = json.loads(stdout)
        self.command_results.append(connect_result)

    def write_report(self) -> None:
        ensure_parent(self.report_path)
        payload = {
            "cloud_dir": str(self.cloud_dir),
            "cloud_port": self.cloud_port,
            "proxy_url": self.proxy.base_url if self.proxy is not None else None,
            "temp_root": str(self.tmp_root),
            "failure": self.failure,
            "commands": [serialize_command_result(result) for result in self.command_results],
            "observed_endpoints": summarize_observed_endpoints(self.command_results),
        }
        self.report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def serialize_command_result(result: CommandResult) -> dict[str, Any]:
    return {
        "name": result.name,
        "cwd": result.cwd,
        "argv": result.argv,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "expected": [asdict(item) for item in result.expected],
        "missing_expected": result.missing_expected,
        "requests": [asdict(item) for item in result.requests],
        "parsed_json": result.parsed_json,
    }


def summarize_observed_endpoints(results: list[CommandResult]) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    for result in results:
        for req in result.requests:
            seen.append(
                {
                    "command": result.name,
                    "method": req.method,
                    "path": req.path,
                    "query": req.query,
                    "status_code": req.status_code,
                }
            )
    return seen


def ensure_json_dict(result: CommandResult, name: str) -> dict[str, Any]:
    if not isinstance(result.parsed_json, dict):
        raise ValidationError(f"{name} did not produce JSON object output\nstdout:\n{result.stdout}")
    return result.parsed_json


def find_missing_expected(requests: list[RecordedRequest], expected: list[ExpectedCall]) -> list[str]:
    missing: list[str] = []
    for item in expected:
        matched = False
        for req in requests:
            if req.method != item.method:
                continue
            if req.path.startswith(item.path_prefix):
                matched = True
                break
        if not matched:
            missing.append(f"{item.method} {item.path_prefix}")
    return missing


def format_observed_requests(requests: list[RecordedRequest]) -> str:
    if not requests:
        return "(none)"
    return ", ".join(f"{req.method} {req.path}" for req in requests)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Boot ../aweb-cloud locally and validate real aw CLI endpoint usage through a recording proxy."
    )
    parser.add_argument("--cloud-dir", type=Path, default=DEFAULT_CLOUD_DIR, help="Path to the aweb-cloud checkout")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="Where to write the JSON report")
    parser.add_argument("--project-slug", default="validator-project", help="Project slug to create")
    parser.add_argument("--namespace-slug", default="", help="Namespace slug for create-project; defaults to project slug")
    parser.add_argument("--cloud-port", type=int, default=0, help="Hosted backend port (0 = auto)")
    parser.add_argument("--postgres-port", type=int, default=0, help="Postgres port (0 = auto)")
    parser.add_argument("--redis-port", type=int, default=0, help="Redis port (0 = auto)")
    parser.add_argument("--skip-stack-up", action="store_true", help="Assume ../aweb-cloud is already running on --cloud-port")
    parser.add_argument("--leave-stack-running", action="store_true", help="Do not stop the local aweb-cloud stack at the end")
    parser.add_argument("--keep-temp", action="store_true", help="Keep the generated temp workspace after the run")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validator = Validator(args)
    if not validator.cloud_dir.exists():
        raise ValidationError(f"cloud dir not found: {validator.cloud_dir}")
    exit_code = 0
    try:
        validator.build_aw()
        if not args.skip_stack_up:
            validator.start_stack()
        validator.start_proxy()
        validator.run_suite()
    except ValidationError as exc:
        validator.failure = str(exc)
        exit_code = 1
    finally:
        validator.write_report()

    print(f"Validation report written to {validator.report_path}")
    print(f"Temp root: {validator.tmp_root}")
    if validator.proxy is not None:
        print(f"Proxy URL: {validator.proxy.base_url}")
    print(f"Observed endpoint calls: {sum(len(result.requests) for result in validator.command_results)}")
    if validator.failure:
        print(validator.failure, file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except ValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
