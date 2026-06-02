"""CLI entry point for the sniffer daemon that listens for knock sequences."""
from __future__ import annotations

import click
from rich.console import Console

from nps_lab_el.models.auth import AuthorizationState, CaptureEvent
from nps_lab_el.models.config import load_config
from nps_lab_el.platform.capture import CaptureBackend, SimulationCapture
from nps_lab_el.platform.permissions import require_privileges
from nps_lab_el.services.auth_engine import AuthEngine
from nps_lab_el.services.drm_responder import DrmResponder

console = Console()


@click.command("sniffer")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True), help="Path to YAML config file.")
@click.option("--iface", default=None, help="Network interface (overrides config).")
@click.option("--verbose", is_flag=True, default=False, help="Enable verbose output.")
@click.option("--simulation", is_flag=True, default=False, help="Simulation mode (no raw sockets).")
def cli(config_path: str, iface: str | None, verbose: bool, simulation: bool) -> None:
    """Start the sniffer daemon to listen for port-knock sequences."""
    cfg = load_config(config_path)

    require_privileges(simulation=simulation)

    iface_resolved = iface or cfg.server.iface

    # Create capture backend
    if simulation:
        capture = SimulationCapture(events=[])
        console.print("[bold cyan]Simulation mode[/bold cyan] — no packets will be captured.")
    else:
        capture = CaptureBackend(iface=iface_resolved, server_ip=cfg.server.ip)

    engine = AuthEngine(cfg)

    drm_responder: DrmResponder | None = None
    if cfg.drm.enabled:
        drm_responder = DrmResponder(cfg)

    # Accumulate events per source IP
    events_by_src: dict[str, list[CaptureEvent]] = {}
    SESSION_GAP = 30.0

    def packet_callback(packet) -> None:
        event = capture.parse_packet(packet)
        if event is None:
            return

        src_ip = event.src

        if src_ip not in events_by_src:
            events_by_src[src_ip] = []

        buf = events_by_src[src_ip]

        # Detect session gap
        if buf and (event.ts - buf[-1].ts) > SESSION_GAP:
            _process_accumulated(src_ip, buf)
            events_by_src[src_ip] = []

        events_by_src[src_ip].append(event)

        if verbose:
            console.print(f"[dim]Event from {src_ip} seq={event.icmp_seq} ts={event.ts:.3f}[/dim]")

    def _process_accumulated(src_ip: str, events: list[CaptureEvent]) -> None:
        if not events:
            return

        session = engine.process_events(events)
        console.print(f"[bold]Session {session.session_id}[/bold] from {src_ip}: {session.state}")

        if session.state == AuthorizationState.AUTHORIZED and drm_responder is not None:
            fragment = drm_responder.compute_fragment(session)
            if verbose:
                console.print(f"[green]DRM fragment: {fragment.hex()}[/green]")

            if not capture.simulation:
                from scapy.all import send as scapy_send

                session_nonce = events[0].icmp_id if events else 0
                reply_pkt = drm_responder.build_reply_packet(
                    src_ip=cfg.server.ip,
                    dst_ip=src_ip,
                    fragment=fragment,
                    session_nonce=session_nonce,
                )
                scapy_send(reply_pkt, verbose=False)
                console.print(f"[green]DRM reply sent to {src_ip}[/green]")

    console.print(f"[bold green]Sniffer started on {iface_resolved}[/bold green]")

    try:
        capture.start_capture(callback=packet_callback)
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down...[/yellow]")
    finally:
        # Process any remaining buffered events
        for src_ip, buf in events_by_src.items():
            _process_accumulated(src_ip, buf)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
