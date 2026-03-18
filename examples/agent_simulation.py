"""
LinkAuth — Interactive Agent Simulation

Simulates a real LLM agent workflow with a mock LLM but REAL broker interaction.
The broker must be running for this example to work.

Start the broker first:
    PYTHONPATH=src python -m uvicorn broker.main:app --port 8080

Then run this example:
    python examples/agent_simulation.py

What happens:
  1. You type anything → Mock-LLM pretends you asked for your last 5 emails
  2. Tool "imap" checks the credential store → no credentials found
  3. Agent initiates LinkAuth session → shows you a real URL + code
  4. You open the URL in your browser, confirm the code, enter credentials
  5. Background poller picks up the encrypted credentials and stores them
  6. You type anything again → Mock-LLM retries the tool
  7. Credentials are found → Mock emails are displayed

The LLM is mocked, but the credential flow is 100% real.

Requires:
    pip install -e ".[examples]"
    pip install rich
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

BROKER_URL = os.environ.get("LINKAUTH_BROKER_URL", "http://localhost:8080/v1")

console = Console()


# ===========================================================================
# Credential Store — real broker communication + background polling
# ===========================================================================

class CredentialStore:
    """Manages credentials via the LinkAuth broker with background polling."""

    def __init__(self, broker_url: str):
        self.broker_url = broker_url
        self._credentials: dict[str, dict] = {}
        self._pending: dict[str, dict] = {}

    def get(self, scope: str) -> dict | None:
        return self._credentials.get(scope)

    def has_pending(self, scope: str) -> bool:
        return scope in self._pending

    def get_challenge(self, scope: str) -> dict | None:
        if scope in self._pending:
            p = self._pending[scope]
            return {"url": p["url"], "code": p["code"]}
        return None

    def request_credentials(self, scope: str, template: str) -> dict:
        """Start a new LinkAuth session and begin background polling."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        public_key_b64 = base64.b64encode(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()

        resp = httpx.post(f"{self.broker_url}/sessions", json={
            "public_key": public_key_b64,
            "template": template,
        })
        resp.raise_for_status()
        session = resp.json()

        self._pending[scope] = {
            "session_id": session["session_id"],
            "code": session["code"],
            "url": session["url"],
            "poll_token": session["poll_token"],
            "private_key": private_key,
        }

        # Start background poller
        t = threading.Thread(
            target=self._poll_loop, args=(scope,), daemon=True
        )
        t.start()

        return {"url": session["url"], "code": session["code"]}

    def _poll_loop(self, scope: str) -> None:
        pending = self._pending.get(scope)
        if not pending:
            return

        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                resp = httpx.get(
                    f"{self.broker_url}/sessions/{pending['session_id']}",
                    headers={"Authorization": f"Bearer {pending['poll_token']}"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data["status"] == "ready" and data.get("ciphertext"):
                        credentials = self._decrypt(
                            pending["private_key"], data["ciphertext"]
                        )
                        self._credentials[scope] = credentials
                        del self._pending[scope]
                        return
            except Exception:
                pass
            time.sleep(2)

    @staticmethod
    def _decrypt(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> dict:
        payload = json.loads(base64.b64decode(ciphertext_b64))
        wrapped_key = base64.b64decode(payload["wrapped_key"])
        aes_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        plaintext = AESGCM(aes_key).decrypt(iv, ciphertext, None)
        return json.loads(plaintext)


# ===========================================================================
# Tool: IMAP email reader (mock, but credential flow is real)
# ===========================================================================

MOCK_EMAILS = [
    {"from": "alice@example.com", "subject": "Meeting tomorrow at 10am", "date": "2026-03-18"},
    {"from": "bob@corp.de", "subject": "Invoice #4521 attached", "date": "2026-03-17"},
    {"from": "newsletter@dev.to", "subject": "Top 10 Python tips this week", "date": "2026-03-17"},
    {"from": "charlie@startup.io", "subject": "Re: API integration questions", "date": "2026-03-16"},
    {"from": "hr@company.com", "subject": "Updated vacation policy", "date": "2026-03-15"},
]


def tool_imap_read(cred_store: CredentialStore, count: int = 5) -> dict:
    """Tool: Read last N emails via IMAP. Requires basic_auth credentials."""
    creds = cred_store.get("imap")

    if creds is None:
        if cred_store.has_pending("imap"):
            challenge = cred_store.get_challenge("imap")
            return {
                "auth_required": True,
                "message": (
                    f"Authentication still pending for 'imap'. "
                    f"Please open {challenge['url']} and verify code: {challenge['code']}"
                ),
                "url": challenge["url"],
                "code": challenge["code"],
            }

        challenge = cred_store.request_credentials("imap", template="basic_auth")
        return {
            "auth_required": True,
            "message": (
                f"Authentication required for 'imap'. "
                f"Please open {challenge['url']} and verify code: {challenge['code']}"
            ),
            "url": challenge["url"],
            "code": challenge["code"],
        }

    return {
        "auth_required": False,
        "emails": MOCK_EMAILS[:count],
        "account": creds.get("username", "unknown"),
    }


# ===========================================================================
# Mock LLM — hardcoded responses, but tool calls are real
# ===========================================================================

def mock_llm_respond(tool_result: dict) -> str:
    if tool_result.get("auth_required"):
        url = tool_result["url"]
        code = tool_result["code"]
        return (
            f"Ich benötige eine Authentifizierung, um auf Ihre E-Mails "
            f"zugreifen zu können.\n\n"
            f"Bitte öffnen Sie diesen Link und bestätigen Sie den Code [bold]{code}[/bold]:\n"
            f"[link={url}]{url}[/link]\n\n"
            f"Geben Sie dort Ihre IMAP-Zugangsdaten ein."
        )

    emails = tool_result.get("emails", [])
    account = tool_result.get("account", "")
    return f"Hier sind Ihre letzten {len(emails)} E-Mails (Account: {account}):"


def display_emails(emails: list[dict]) -> None:
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Date", style="dim", width=12)
    table.add_column("From", width=25)
    table.add_column("Subject")

    for i, mail in enumerate(emails, 1):
        table.add_row(str(i), mail["date"], mail["from"], mail["subject"])

    console.print(table)


# ===========================================================================
# Main — Interactive agent loop
# ===========================================================================

def main():
    info = [
        "[bold cyan]LinkAuth Agent Simulation[/bold cyan]\n",
        "Simulates an LLM agent that needs IMAP credentials.",
        "The LLM is mocked, but the credential flow is [bold]100% real[/bold].\n",
        f"Broker:   {BROKER_URL}",
        "Template: basic_auth (username + password)",
        "",
        "[dim]Type anything to interact. Type 'quit' to exit.[/dim]",
    ]
    console.print(Panel("\n".join(info), expand=False))

    cred_store = CredentialStore(BROKER_URL)
    state = "need_auth"  # need_auth | waiting_auth | has_auth

    while True:
        try:
            user_input = console.input("\n[bold green]You:[/bold green] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Chat ended.[/dim]")
            break

        if user_input.lower() in ("quit", "exit", "q"):
            console.print("[dim]Chat ended.[/dim]")
            break

        if not user_input:
            continue

        # Mock-LLM decides to call the imap tool
        tool_name = "imap_read(count=5)"
        action = "retrying" if state == "waiting_auth" else "calling"
        console.print(Panel(
            f"call_executed=True  call_failed=False\n"
            f"tool: {tool_name}  action: {action}",
            title="DriverResponse",
            border_style="dim",
        ))
        console.print("[dim]Tool executed -- streaming next LLM turn...[/dim]")

        # Execute the tool (real broker interaction!)
        result = tool_imap_read(cred_store, count=5)

        # Mock-LLM generates response
        response_text = mock_llm_respond(result)

        if result.get("auth_required"):
            state = "waiting_auth"
            console.print(f"\n[bold blue]Assistant:[/bold blue] {response_text}")
        else:
            state = "has_auth"
            console.print(f"\n[bold blue]Assistant:[/bold blue] {response_text}")
            display_emails(result["emails"])

            console.print(Panel(
                "[bold green]Roundtrip complete![/bold green]\n"
                "The broker never saw your credentials in plaintext.\n"
                "They were encrypted in your browser and decrypted by the agent.",
                expand=False,
            ))
            break


if __name__ == "__main__":
    main()
