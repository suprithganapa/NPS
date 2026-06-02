#!/usr/bin/env python3
"""
NPS LAB EL — Video DRM Demo
============================
Demonstrates that the encrypted video is locked behind an ICMP knock sequence.

Two clients are simulated:
  CLIENT A — does NOT have the correct TOTP secret → CANNOT decrypt video
  CLIENT B — has the correct TOTP secret, sends valid knock → decrypts video

Run:
    python demo.py

No raw sockets needed — fully simulated.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

ROOT = Path(__file__).parent
console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]NPS LAB EL — Stealth ICMP Video DRM Demo[/bold cyan]\n"
        "[dim]Single-Packet Authorization via ICMP jitter timing[/dim]",
        border_style="cyan",
    ))
    console.print()
    console.print("[bold]Concept:[/bold]")
    console.print("  Unlike port-knocking (which sends packets to specific TCP/UDP ports),")
    console.print("  this system hides the secret in the [bold yellow]timing gaps[/bold yellow] between")
    console.print("  consecutive ICMP Echo (ping) packets.")
    console.print()
    console.print("  bit [bold]0[/bold] → wait [bold]20 ms[/bold]  before the next ping")
    console.print("  bit [bold]1[/bold] → wait [bold]25 ms[/bold]  before the next ping")
    console.print()
    console.print("  512 packets × ~20 ms = [bold green]~10 seconds[/bold green] to transmit the full token")
    console.print()


def _section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold]{title}[/bold]", style="bright_blue"))
    console.print()


def _ok(msg: str) -> None:
    console.print(f"  [bold green]✓[/bold green]  {msg}")


def _fail(msg: str) -> None:
    console.print(f"  [bold red]✗[/bold red]  {msg}")


def _info(msg: str) -> None:
    console.print(f"  [dim]→[/dim]  {msg}")


# ---------------------------------------------------------------------------
# Step 1: prepare artifacts
# ---------------------------------------------------------------------------

def prepare_artifacts() -> tuple[Path, Path, Path]:
    """Ensure encrypted video + manifest + server key fragment all exist."""
    _section("Step 1 — Preparing encrypted video artifact")

    video_path = ROOT / "artifacts" / "sample_video.mp4"
    enc_path   = ROOT / "artifacts" / "sample_video.enc"
    manifest_p = ROOT / "artifacts" / "sample_video.manifest.json"
    keyfrag_p  = ROOT / "server_secrets" / "sample_video.keyfrag"

    if not video_path.exists():
        _info("Generating minimal sample MP4…")
        from scripts.generate_sample_video import make_mp4
        video_path.write_bytes(make_mp4())

    if not enc_path.exists() or not keyfrag_p.exists():
        _info("Encrypting video with AES-256-GCM…")
        _run_encrypt(video_path)

    manifest = json.loads(manifest_p.read_text())
    key_fragment_server = keyfrag_p.read_bytes()

    _ok(f"Encrypted artifact : {enc_path.name}  ({enc_path.stat().st_size} bytes)")
    _ok(f"Manifest           : {manifest_p.name}")
    _ok(f"Server key fragment: [dim](held server-side only, 4 bytes)[/dim]")
    _info(f"Plaintext SHA-256  : {manifest['plaintext_sha256'][:32]}…")

    return enc_path, manifest_p, keyfrag_p


def _run_encrypt(video_path: Path) -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plaintext = video_path.read_bytes()
    key = os.urandom(32)
    key_partial, key_fragment = key[:28], key[28:]
    nonce = os.urandom(12)
    aad = b"nps-lab-el-drm-v1"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    artifacts = ROOT / "artifacts"
    artifacts.mkdir(exist_ok=True)
    (artifacts / "sample_video.enc").write_bytes(ciphertext)

    manifest = {
        "artifact": "sample_video.enc",
        "source_filename": video_path.name,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "key_partial_b64": base64.b64encode(key_partial).decode(),
        "aad_b64": base64.b64encode(aad).decode(),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_size": len(plaintext),
    }
    (artifacts / "sample_video.manifest.json").write_text(json.dumps(manifest, indent=2))

    secrets = ROOT / "server_secrets"
    secrets.mkdir(exist_ok=True)
    (secrets / "sample_video.keyfrag").write_bytes(key_fragment)


# ---------------------------------------------------------------------------
# Shared auth helpers
# ---------------------------------------------------------------------------

TOTP_SECRET  = "JBSWY3DPEHPK3PXP"   # correct secret (known to server + Client B)
WRONG_SECRET = "AAAAAAAAAAAAAAAA"    # Client A's wrong secret
WINDOW       = 60


def _get_counter() -> int:
    import math
    return math.floor(time.time() / WINDOW)


def _build_token(secret: str) -> "AuthToken":
    from nps_lab_el.crypto.totp import get_counter
    from nps_lab_el.models.auth import AuthToken

    payload = os.urandom(16)
    counter = get_counter(WINDOW)
    mask = 0x01
    mac_input = payload + counter.to_bytes(8, "big") + mask.to_bytes(1, "big")
    mac = hmac.new(secret.encode(), mac_input, hashlib.sha256).digest()[:16]
    return AuthToken(payload=payload, totp_counter=counter, channel_mask=mask, mac=mac)


def _simulate_knock(token: "AuthToken") -> list:
    """Encode token → jitter IATs → fake CaptureEvents (no real packets sent)."""
    from nps_lab_el.models.auth import CaptureEvent
    from nps_lab_el.protocol.encode_jitter import encode_with_fec

    bits = token.to_bits()
    iats = encode_with_fec(bits, n=32, k=28, t0_ms=20, delta_ms=5)
    events = []
    t = 0.0
    events.append(CaptureEvent(ts=t, src="CLIENT", dst="SERVER",
                               icmp_id=0, icmp_seq=0, ip_id=0, ttl=64, tos=0, icmp_type=8))
    for i, iat in enumerate(iats):
        t += iat
        events.append(CaptureEvent(ts=t, src="CLIENT", dst="SERVER",
                                   icmp_id=0, icmp_seq=i+1, ip_id=0, ttl=64, tos=0, icmp_type=8))
    return events


def _server_verify(events: list, correct_secret: str) -> tuple[bool, str]:
    """Server-side: decode knock and verify TOTP+MAC."""
    from nps_lab_el.models.config import (
        AppConfig, AuthConfig, ChannelsConfig, FecConfig,
        FirewallConfig, JitterConfig, ServerConfig, TargetsConfig,
    )
    from nps_lab_el.services.auth_engine import AuthEngine

    cfg = AppConfig(
        server=ServerConfig(ip="SERVER", iface="eth0"),
        auth=AuthConfig(totp_secret=correct_secret, window_seconds=WINDOW, ttl_auth_seconds=300),
        channels=ChannelsConfig(jitter=JitterConfig(enabled=True, t0_ms=20, delta_ms=5, tau_ms=2)),
        fec=FecConfig(enabled=True, n=32, k=28),
        targets=TargetsConfig(allowlist=[]),
        firewall=FirewallConfig(mode="log_only"),
    )
    engine = AuthEngine(cfg)
    session = engine.process_events(events)
    return session.state.value == "AUTHORIZED", session.state.value


def _server_deliver_fragment(keyfrag_path: Path) -> bytes:
    """Server reads stored key fragment and 'sends' it via ICMP reply."""
    return keyfrag_path.read_bytes()


def _decrypt_video(enc_path: Path, manifest_p: Path, key_fragment: bytes) -> bytes | None:
    from nps_lab_el.crypto.aes_gcm import decrypt_artifact
    from nps_lab_el.models.auth import KeyMaterial

    manifest = json.loads(manifest_p.read_text())
    ciphertext = enc_path.read_bytes()
    key_partial = base64.b64decode(manifest["key_partial_b64"])
    nonce = base64.b64decode(manifest["nonce_b64"])
    aad = base64.b64decode(manifest["aad_b64"])

    km = KeyMaterial(key_partial=key_partial, key_fragment=key_fragment)
    try:
        return decrypt_artifact(ciphertext, km.key_full, nonce, aad)
    except Exception:
        return None


def _verify_video(plaintext: bytes, manifest_p: Path) -> bool:
    manifest = json.loads(manifest_p.read_text())
    return hashlib.sha256(plaintext).hexdigest() == manifest["plaintext_sha256"]


# ---------------------------------------------------------------------------
# Client A — wrong secret, cannot knock
# ---------------------------------------------------------------------------

def demo_client_a(enc_path: Path, manifest_p: Path, keyfrag_path: Path) -> None:
    _section("CLIENT A — No valid knock (wrong TOTP secret)")

    console.print("  Client A has the encrypted video file but [bold red]does NOT know[/bold red]")
    console.print("  the correct TOTP secret shared with the server.")
    console.print()

    _info(f"Client A TOTP secret : [bold red]{WRONG_SECRET}[/bold red]  (wrong)")
    _info(f"Server TOTP secret   : [bold green]{TOTP_SECRET}[/bold green]  (correct)")
    console.print()

    # Client A builds a token with the wrong secret
    _info("Client A builds AuthToken with wrong secret and sends ICMP knock…")
    token_a = _build_token(WRONG_SECRET)
    events_a = _simulate_knock(token_a)
    _info(f"Sent {len(events_a)} ICMP packets  (timing sequence encodes wrong token)")
    console.print()

    # Server tries to verify
    _info("Server receives knock, decodes IATs, reconstructs token…")
    authorized, state = _server_verify(events_a, TOTP_SECRET)

    if authorized:
        _fail("Server unexpectedly authorized — this should not happen!")
        sys.exit(1)
    else:
        _ok(f"Server decision: [bold red]{state}[/bold red]  (TOTP+MAC mismatch)")
    console.print()

    # Client A tries to decrypt without fragment
    _info("Client A attempts decryption using only key_partial (no fragment)…")

    # Attempt with a random wrong fragment
    wrong_fragment = os.urandom(4)
    plaintext = _decrypt_video(enc_path, manifest_p, wrong_fragment)

    if plaintext is None:
        _ok("[bold red]Decryption failed[/bold red] — AES-GCM authentication tag rejected")
        _fail("Client A [bold red]CANNOT[/bold red] access the video  ✗")
    else:
        _fail("Client A decrypted the video — this should NOT happen!")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Client B — correct secret, valid knock
# ---------------------------------------------------------------------------

def demo_client_b(enc_path: Path, manifest_p: Path, keyfrag_path: Path) -> None:
    _section("CLIENT B — Valid knock (correct TOTP secret)")

    console.print("  Client B shares the correct TOTP secret with the server.")
    console.print("  It encodes a valid AuthToken into ICMP timing and sends the knock.")
    console.print()

    _info(f"Client B TOTP secret : [bold green]{TOTP_SECRET}[/bold green]  (correct)")
    console.print()

    _info("Client B builds AuthToken with correct secret…")
    token_b = _build_token(TOTP_SECRET)
    _info(f"  totp_counter = {token_b.totp_counter}")
    _info(f"  channel_mask = 0x{token_b.channel_mask:02x}  (JITTER channel)")
    console.print()

    _info("Encoding 328-bit token → RS(32,28) FEC → 512-symbol jitter sequence…")
    events_b = _simulate_knock(token_b)
    _info(f"Sent {len(events_b)} ICMP packets at 20ms/25ms intervals  (~10s on real network)")
    console.print()

    _info("Server decodes IATs → reconstructs bits → RS-decodes → AuthToken…")
    authorized, state = _server_verify(events_b, TOTP_SECRET)

    if not authorized:
        _fail(f"Server returned {state} — unexpected failure. Check TOTP clock skew.")
        sys.exit(1)

    _ok(f"Server decision: [bold green]{state}[/bold green]")
    console.print()

    _info("Server embeds 32-bit key fragment into ICMP Echo Reply (TTL + ToS + ICMP ID)…")
    key_fragment = _server_deliver_fragment(keyfrag_path)
    _ok(f"Client B received key fragment: [bold cyan]{key_fragment.hex()}[/bold cyan]  (4 bytes via ICMP reply headers)")
    console.print()

    _info("Client B assembles full AES-256 key:  key_partial (28 bytes) ‖ key_fragment (4 bytes)")
    _info("Decrypting video in RAM with AES-256-GCM…")
    plaintext = _decrypt_video(enc_path, manifest_p, key_fragment)

    if plaintext is None:
        _fail("Decryption failed — unexpected error!")
        sys.exit(1)

    if not _verify_video(plaintext, manifest_p):
        _fail("SHA-256 mismatch — data corrupted!")
        sys.exit(1)

    out_path = ROOT / "artifacts" / "sample_video_decrypted.mp4"
    out_path.write_bytes(plaintext)

    _ok(f"[bold green]Decryption successful![/bold green]  SHA-256 verified")
    _ok(f"Video written to: [bold]{out_path}[/bold]  ({len(plaintext)} bytes)")
    _ok(f"Client B [bold green]CAN[/bold green] access the video  ✓")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def summary() -> None:
    _section("Summary")

    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("", style="bold", width=10)
    t.add_column("TOTP secret", width=20)
    t.add_column("Knock result", width=16)
    t.add_column("Key fragment", width=16)
    t.add_column("Video access", width=14)

    t.add_row("Client A", f"[red]{WRONG_SECRET}[/red]", "[red]DENIED[/red]",
              "[red]NOT delivered[/red]", "[bold red]BLOCKED ✗[/bold red]")
    t.add_row("Client B", f"[green]{TOTP_SECRET}[/green]", "[green]AUTHORIZED[/green]",
              "[green]Delivered[/green]", "[bold green]ALLOWED ✓[/bold green]")

    console.print(t)
    console.print()
    console.print("[bold]How the lock works:[/bold]")
    console.print("  The video is encrypted with AES-256-GCM.")
    console.print("  The manifest contains [bold]28 of the 32[/bold] key bytes (key_partial).")
    console.print("  The remaining [bold]4 bytes[/bold] (key_fragment) never leave the server")
    console.print("  until a client completes a valid ICMP knock.")
    console.print("  Without the fragment, AES-GCM authentication [bold red]always fails[/bold red].")
    console.print()
    console.print("[bold]What 'knocking' means here (not ports!):[/bold]")
    console.print("  The client sends a burst of plain ICMP Echo Requests (pings).")
    console.print("  The [bold yellow]time gap[/bold yellow] between consecutive pings encodes one bit:")
    console.print("    20 ms gap → bit 0")
    console.print("    25 ms gap → bit 1")
    console.print("  No special ports are opened or closed.")
    console.print("  A passive observer sees normal-looking ICMP traffic.")
    console.print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _banner()
    enc_path, manifest_p, keyfrag_path = prepare_artifacts()
    demo_client_a(enc_path, manifest_p, keyfrag_path)
    demo_client_b(enc_path, manifest_p, keyfrag_path)
    summary()
