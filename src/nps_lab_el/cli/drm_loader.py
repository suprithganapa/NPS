"""CLI entry point for loading and decrypting DRM-protected artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import click
from rich.console import Console

from nps_lab_el.crypto.aes_gcm import decrypt_artifact
from nps_lab_el.models.auth import KeyMaterial
from nps_lab_el.models.config import load_config
from nps_lab_el.services.drm_responder import DrmResponder

console = Console()


@click.command("drm-load")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True), help="Path to YAML config file.")
@click.option("--artifact", required=True, type=click.Path(exists=True), help="Path to .enc encrypted artifact.")
@click.option("--manifest", required=True, type=click.Path(exists=True), help="Path to .manifest.json file.")
@click.option("--simulation", is_flag=True, default=False, help="Simulation mode (generate fake fragment).")
def cli(config_path: str, artifact: str, manifest: str, simulation: bool) -> None:
    """Decrypt a DRM-protected artifact using a key fragment from knock authorization."""
    cfg = load_config(config_path)

    # Load manifest
    with open(manifest) as f:
        manifest_data = json.load(f)

    artifact_name: str = manifest_data["artifact"]
    nonce = base64.b64decode(manifest_data["nonce_b64"])
    key_partial = base64.b64decode(manifest_data["key_partial_b64"])
    aad = base64.b64decode(manifest_data["aad_b64"])
    expected_sha256: str = manifest_data["plaintext_sha256"]

    # Load encrypted artifact
    with open(artifact, "rb") as f:
        ciphertext = f.read()

    console.print(f"[bold]Artifact:[/bold] {artifact_name}")
    console.print(f"[bold]Ciphertext size:[/bold] {len(ciphertext)} bytes")

    if simulation:
        if "key_fragment_b64" in manifest_data:
            key_fragment = base64.b64decode(manifest_data["key_fragment_b64"])
            console.print("[bold cyan]Simulation mode[/bold cyan] — using manifest key fragment.")
        else:
            from nps_lab_el.crypto.aes_gcm import compute_key_fragment_hmac
            from nps_lab_el.crypto.totp import get_counter

            counter = get_counter(cfg.auth.window_seconds)
            key_fragment = compute_key_fragment_hmac(
                key_deriv=cfg.auth.totp_secret.encode(),
                totp_counter=counter,
                src_ip=cfg.server.ip,
            )
            console.print("[bold cyan]Simulation mode[/bold cyan] — using computed key fragment.")
    else:
        # Wait for ICMP reply carrying the key fragment
        console.print("[bold yellow]Waiting for knock authorization and ICMP reply...[/bold yellow]")

        from scapy.all import ICMP, IP, sniff

        reply_packets = sniff(
            filter="icmp",
            count=1,
            timeout=120,
        )

        if not reply_packets:
            console.print("[bold red]Timeout: no ICMP reply received.[/bold red]")
            sys.exit(1)

        pkt = reply_packets[0]
        if not pkt.haslayer(IP) or not pkt.haslayer(ICMP):
            console.print("[bold red]Invalid reply packet.[/bold red]")
            sys.exit(1)

        ip_layer = pkt[IP]
        icmp_layer = pkt[ICMP]

        # Use icmp_id as session nonce (matching sniffer_daemon convention)
        session_nonce = 0  # default; in production this would be negotiated
        key_fragment = DrmResponder.extract_key_fragment(
            reply_ttl=ip_layer.ttl,
            reply_tos=ip_layer.tos,
            reply_icmp_id=icmp_layer.id,
            session_nonce=session_nonce,
        )

    # Combine keys
    km = KeyMaterial(key_partial=key_partial, key_fragment=key_fragment)
    full_key = km.key_full

    # Decrypt
    try:
        plaintext = decrypt_artifact(ciphertext, full_key, nonce, aad)
    except Exception as exc:
        console.print(f"[bold red]Decryption failed:[/bold red] {exc}")
        sys.exit(1)

    # Verify SHA-256
    actual_sha256 = hashlib.sha256(plaintext).hexdigest()
    if actual_sha256 == expected_sha256:
        console.print(f"[bold green]Decryption successful.[/bold green] SHA-256 verified: {actual_sha256}")
    else:
        console.print(f"[bold red]SHA-256 mismatch![/bold red] expected={expected_sha256} actual={actual_sha256}")
        sys.exit(1)

    # Write decrypted output
    out_path = artifact.removesuffix(".enc")
    if out_path == artifact:
        out_path = artifact + ".decrypted"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    console.print(f"[bold]Decrypted artifact written to:[/bold] {out_path}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
